using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using SteamKit2;
using SteamKit2.Internal;
using Xunit;

namespace Tests
{
    public class EndToEndFacts
    {
        [Fact]
        public void SteamClientConnects()
        {
            var server = new MockCMServer();
            server.AddConfigurator(new CryptoSetupConfigurator());

            var steamClient = new SteamClient() { KeyDictionary = new MockKeyProvider() };
            var callbackMgr = new CallbackManager(steamClient);
            
            var wait = new ManualResetEvent(initialState: false);
            callbackMgr.Subscribe<SteamClient.ConnectedCallback>(_ => { wait.Set(); });

            using (server.Run())
            {
                steamClient.Connect(server.LocalEndPoint);
                RunCallbackMgr(callbackMgr, TimeSpan.FromSeconds(10), wait);

                var gotCallback = wait.WaitOne(0);
                Assert.True(gotCallback, "Should have connected.");
            }
        }

        static void RunCallbackMgr(CallbackManager callbackMgr, TimeSpan timeout, WaitHandle waitHandle)
        {
            using (var cancellation = new CancellationTokenSource())
            {
                cancellation.CancelAfter(timeout);

                while (!waitHandle.WaitOne(0) && !cancellation.IsCancellationRequested)
                {
                    callbackMgr.RunWaitCallbacks(TimeSpan.FromMilliseconds(50));
                }
            }
        }

        sealed class CryptoSetupConfigurator : IMockCMClientConfigurator
        {
            public void Configure(MockCMClient client)
            {
                client.RegisterMessageHandler(EMsg.ChannelEncryptResponse, packetMsg =>
                {
                    var response = new Msg<MsgChannelEncryptResponse>(packetMsg);
                    var keySize = response.Body.KeySize;
                    byte[] encryptedSessionKey;
                    int crc;
                    using (var reader = new BinaryReader(response.Payload))
                    {
                        encryptedSessionKey = reader.ReadBytes((int)keySize);
                        crc = reader.ReadInt32();
                    }

                    byte[] sessionKey = null;

                    EResult result;

                    try
                    {
                        using (var rsa = new RSACryptoServiceProvider())
                        {
                            rsa.PersistKeyInCsp = false;
                            MockKeyProvider.LoadPrivateKey(rsa);

                            sessionKey = rsa.Decrypt(encryptedSessionKey, fOAEP: true);
                        }
                        result = EResult.OK;
                    }
                    catch (CryptographicException)
                    {
                        result = EResult.EncryptionFailure;
                    }

                    var encryptResult = new Msg<MsgChannelEncryptResult>();
                    encryptResult.Body.Result = result;
                    client.Send(encryptResult);

                    if (sessionKey != null)
                    {
                        client.NetFilterEncryption = new NetFilterEncryption(sessionKey);
                    }
                });
            }
        }
    }
}
