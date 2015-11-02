using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using SteamKit2;
using SteamKit2.Internal;

namespace Tests
{
	interface IMockCMClientConfigurator
	{
		void Configure(MockCMClient client);
	}

	class MockCMClient
	{
		public MockCMClient(TcpClient client)
		{
			this.client = client;
			stream = client.GetStream();
			stream.ReadTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;
			networkThread = new Thread(NetworkThreadStart);
		}

		readonly TcpClient client;
		readonly NetworkStream stream;
		readonly Thread networkThread;
		readonly CancellationTokenSource cts = new CancellationTokenSource();
		readonly object writeLock = new object();
		readonly ConcurrentDictionary<EMsg, ConcurrentBag<Action<IPacketMsg>>> messageHandlers = new ConcurrentDictionary<EMsg, ConcurrentBag<Action<IPacketMsg>>>();

		public NetFilterEncryption NetFilterEncryption { get; set; }

		public void RegisterMessageHandler(EMsg eMsg, Action<IPacketMsg> action)
		{
			var bag = messageHandlers.GetOrAdd(eMsg, _ => new ConcurrentBag<Action<IPacketMsg>>());
			bag.Add(action);
		}

		public void OnMessageReceived(IPacketMsg msg)
		{
			ConcurrentBag<Action<IPacketMsg>> bag;
			if (!messageHandlers.TryGetValue(msg.MsgType, out bag))
			{
				return;
			}
			
			foreach(var action in bag.ToArray())
			{
				action(msg);
			}
		}
		
		public void Start()
		{
			networkThread.Start();
		}

		void Abort()
		{
			client.Close();
			cts.Cancel();
		}

		public void Close()
		{
			Abort();
			networkThread.Join();
		}

		public void Dispose()
		{
			Close();
			cts.Dispose();
		}

		public void Send(IClientMsg msg)
		{
			byte[] data;
			using (var ms = new MemoryStream())
			using (var writer = new BinaryWriter(ms))
			{
				var message = msg.Serialize();

				message = NetFilterEncryption?.ProcessOutgoing(message) ?? message;

				writer.Write((uint)message.Length);
				writer.Write(TcpConnection.MAGIC);
				writer.Write(message);

				writer.Flush();

				data = ms.ToArray();
			}

			stream.Write(data, 0, data.Length);
		}

		void NetworkThreadStart()
		{
			var cancellationToken = cts.Token;

			var encryptRequest = new Msg<MsgChannelEncryptRequest>();
			encryptRequest.Body.Universe = EUniverse.Dev;
			Send(encryptRequest);

			while (!cancellationToken.IsCancellationRequested)
			{
				byte[] data;

				try
				{
					var buffer = new byte[4];
					var bytesRead = stream.Read(buffer, 0, buffer.Length);
					if (bytesRead < buffer.Length)
					{
						Abort();
						return;
					}

					var length = BitConverter.ToInt32(buffer, 0);
					if (length < sizeof(uint))
					{
						Abort();
					}
					
					bytesRead = stream.Read(buffer, 0, buffer.Length);
					if (bytesRead < buffer.Length)
					{
						Close();
						return;
					}

					var magic = BitConverter.ToUInt32(buffer, 0);
					if (magic != TcpConnection.MAGIC)
					{
						Abort();
					}

					data = new byte[length];
					bytesRead = stream.Read(data, 0, data.Length);
					if (bytesRead < data.Length)
					{
						Abort();
						return;
					}
				}
				catch (IOException ex) when ((ex.InnerException as SocketException)?.SocketErrorCode == SocketError.TimedOut)
				{
					continue;
				}
				catch (IOException ex)
				{
					Trace.WriteLine($"Caught IOException in {nameof(MockCMClient)}: {ex.Message}");
					Abort();
					return;
				}

				data = NetFilterEncryption?.ProcessIncoming(data) ?? data;
				var packetMsg = CMClient.GetPacketMsg(data);
				OnMessageReceived(packetMsg);
			}
		}
	}

	class MockKeyProvider : IKeyDictionary
	{
		public byte[] GetPublicKey(EUniverse eUniverse)
		{
			return new byte[]
			{
				0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
				0x01, 0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xDB,
				0x6D, 0xD1, 0xB4, 0x6A, 0x58, 0x45, 0xE9, 0xE9, 0x33, 0xE7, 0xE1, 0xE5, 0x67, 0xA3, 0xBC,
				0x31, 0x02, 0x49, 0xC8, 0x23, 0x3E, 0xA1, 0x6C, 0x38, 0x94, 0xB0, 0xA4, 0xCB, 0x1F, 0x15,
				0x18, 0x9F, 0x58, 0xE3, 0x71, 0x9F, 0xB1, 0x29, 0xC9, 0x03, 0xE5, 0x7C, 0xB4, 0xE6, 0xFB,
				0x08, 0x08, 0x12, 0xA1, 0xB1, 0x24, 0xA3, 0xCC, 0xD9, 0x7F, 0xA5, 0x50, 0x15, 0x1C, 0x42,
				0x87, 0x57, 0xC0, 0x26, 0x89, 0xAA, 0x04, 0x9D, 0x16, 0x18, 0xBE, 0xA2, 0xF9, 0x06, 0x48,
				0xB4, 0xA8, 0xED, 0x8B, 0xC8, 0x4C, 0xE1, 0xC0, 0xF4, 0xE2, 0xA0, 0x44, 0xC9, 0x7E, 0x1E,
				0xE2, 0x50, 0xA1, 0x38, 0xB4, 0xA3, 0xA2, 0xB6, 0x3A, 0x1C, 0xC1, 0x85, 0xFD, 0xB7, 0x5F,
				0xD6, 0x70, 0x14, 0xBF, 0x7A, 0x39, 0xBA, 0xCD, 0x4E, 0x04, 0xA9, 0x35, 0x2A, 0x2B, 0x3E,
				0xE4, 0xBE, 0xA4, 0xA7, 0xA4, 0xCC, 0x79, 0x02, 0x03, 0x01, 0x00, 0x01
			};
		}

		public static void LoadPrivateKey(AsymmetricAlgorithm algorithm)
		{
			var xml = @"
<RSAKeyValue><Modulus>223RtGpYRenpM+fh5WejvDECScgjPqFsOJSwpMsfFRifWONxn7EpyQPlfLTm+wgIEqGxJKPM2X+lUBUcQodXwCaJqgSdFhi+ovkGSLSo7YvITOHA9OKgRMl+HuJQoTi0o6K2OhzBhf23X9ZwFL96ObrNTgSpNSorPuS+pKekzHk=</Modulus>
	<Exponent>AQAB</Exponent>
	<P>8hu+nLMTcAoQ/6Ov1YTqEgk0px2gyBW9lhlub7lQ1NfyKIVkhayW09VtjBzYTfYKv4aYRdOxvnOhw50X0Jis3Q==</P>
	<Q>6ATxpDh0e4qOvjXeigm+uvsMLz5e7MG5A8aFlcmwdBre1gUb2qvZbD7aw8iV/fUKIdJImMXyP5VzAxxJ91AmTQ==</Q>
	<DP>0IJohRgM838X6LKWarOPy3y2Jf70S529q5m3bO0S2lwoqBFJ434iX8n+EJ9/ApWV6CEI34pUGAwKEygmLHZw2Q==</DP>
	<DQ>2i/8BVDJyXvNLHaAJhNv92oqVSs0HTU4BaLk8K1QcH7sWxtGzGaa+j5Jf5/b3YxX0OJtPq23V6/1DlHGBPqsaQ==</DQ>
	<InverseQ>5G86rYNJ+4WjYEJE7REQ4ENkqSWerbunqYwup/VNjzGCh/ux6JEYJoDo0ag86pdK/+iIRyM50GE//BgvhmYVpQ==</InverseQ>
	<D>r4f4O0Te/H6T6MvULzlrB76EwBTz7MQg2FpJvGoooS2jOu4nFMIaVQ1i5RGpvKK+InlqRY8q7cpoqdlZU/cEv9xMFZDwVnXWp+MMcrplWxzno2LyDhfkDNyWwF8Ftq2K9UATIm+P+K5M6yLbgy/qEGZL9ox943nUkrCVMNvdeSE=</D>
	<Modulus>ANtt0bRqWEXp6TPn4eVno7wxAknIIz6hbDiUsKTLHxUYn1jjcZ+xKckD5Xy05vsICBKhsSSjzNl/pVAVHEKHV8AmiaoEnRYYvqL5Bki0qO2LyEzhwPTioETJfh7iUKE4tKOitjocwYX9t1/WcBS/ejm6zU4EqTUqKz7kvqSnpMx5</Modulus>
</RSAKeyValue>";

			algorithm.FromXmlString(xml);
		}
	}

	class MockCMServer
	{
		const int DefaultPortNumber = 27011;

		public MockCMServer()
			: this(DefaultPortNumber)
		{
		}

		public MockCMServer(int port)
			: this(new IPEndPoint(IPAddress.Loopback, port))
		{
		}

		public MockCMServer(IPEndPoint localEndPoint)
		{
			listener = new TcpListener(localEndPoint);
		}

		readonly TcpListener listener;
		readonly List<MockCMClient> clients = new List<MockCMClient>();
		readonly List<IMockCMClientConfigurator> configurators = new List<IMockCMClientConfigurator>();
		readonly object clientListLock = new object();

		public IPEndPoint LocalEndPoint => (IPEndPoint)listener.LocalEndpoint;

		public IList<MockCMClient> Clients => clients;

		public IDisposable Run()
		{
			Start();
			return new StopDisposable(this);
		}

		public void AddConfigurator(IMockCMClientConfigurator configurator) => configurators.Add(configurator);

		void Start()
		{
			listener.Start();
			ListenForNextTcpClient();
		}

		void ListenForNextTcpClient()
		{
			var ar = listener.BeginAcceptTcpClient(OnAcceptTcpClient, null);
			if (ar.CompletedSynchronously)
			{
				OnAcceptTcpClient(ar);
			}
		}

		void OnAcceptTcpClient(IAsyncResult ar)
		{
			TcpClient tcpClient;
			try
			{
				tcpClient = listener.EndAcceptTcpClient(ar);
			}
			catch (ObjectDisposedException)
			{
				return;
			}

			var mockClient = new MockCMClient(tcpClient);

			foreach (var configurator in configurators)
			{
				configurator.Configure(mockClient);
			}

			mockClient.Start();

			lock (clientListLock)
			{
				clients.Add(mockClient);
			}
			ListenForNextTcpClient();
		}

		void Stop()
		{
			listener.Stop();

			lock (clientListLock)
			{
				foreach (var client in clients)
				{
					client.Close();
					client.Dispose();
				}
				clients.Clear();
			}
		}

		sealed class StopDisposable : IDisposable
		{
			public StopDisposable(MockCMServer server)
			{
				this.server = server;
			}

			MockCMServer server;

			public void Dispose()
			{
				server.Stop();
			}
		}
	}
}
