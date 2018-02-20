using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace _180202WPF_Wireshark
{
    public partial class MainWindow : Window
    {
        static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
        static PacketDevice selectedDevice = allDevices[0];

        public MainWindow(int deviceIndex)
        {
            InitializeComponent();

            selectedDevice = allDevices[deviceIndex];
            lblNIC.Content = selectedDevice.Description;

            btnReset.IsEnabled = false;
            btnStop.IsEnabled = false;

            cmbFilter.Items.Add("No Filter");
            cmbFilter.Items.Add("Destination IP");
            cmbFilter.Items.Add("Source IP");
            cmbFilter.Items.Add("Destination Port No");
            cmbFilter.Items.Add("Source Port No");
            cmbFilter.SelectedIndex = 0;
        }

        public void Dinle()
        {
            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }

                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip"))
                {
                    communicator.SetFilter(filter);
                }

                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        IpV4Datagram ip;
        UdpDatagram udp;
        TcpDatagram tcp;

        int sayac = 0;
        bool filter = true;

        List<Resource> items = new List<Resource>();
        Dictionary<int, Packet> paketler = new Dictionary<int, Packet>();

        public void PacketHandler(Packet packet)
        {
            ip = packet.Ethernet.IpV4;
            udp = ip.Udp;
            tcp = ip.Tcp;

            filter = false;
            if (ip != null)
            {
                cmbFilter.Dispatcher.Invoke(() =>
                {
                    filter = Query();
                });
            }

            if (filter)
            {
                //System.InvalidOperationException: ‘The calling thread cannot access this object because a different thread owns it.
                dataGrid.Dispatcher.Invoke(() =>
                {
                    var data = new Resource
                    {
                        No = sayac,
                        Time = DateTime.Now.ToString("HH:mm:ss"),
                        SourceIP = ip.Source.ToString(),
                        DestinationIP = ip.Destination.ToString(),
                        TTL = ip.Ttl.ToString(),
                        Length = packet.Length.ToString(),
                        Protocol = ip.Protocol.ToString()
                    };
                    dataGrid.Items.Add(data);
                });
                paketler.Add(sayac, packet);
                sayac++;
            }
            Thread.Sleep(100);
        }

        public bool Query()
        {
            if (cmbFilter.Text == "No Filter")
                filter = true;
            else if (cmbFilter.Text == "Destination IP" && ip.Destination.ToString() == txtFilter.Text)
                filter = true;
            else if (cmbFilter.Text == "Source IP" && ip.Source.ToString() == txtFilter.Text)
                filter = true;
            else if (cmbFilter.Text == "Destination Port No" && udp.DestinationPort.ToString() == txtFilter.Text)
                filter = true;
            else if (cmbFilter.Text == "Source Port No" && udp.SourcePort.ToString() == txtFilter.Text)
                filter = true;

            return filter;
        }

        Thread trDinle;
        private void btnScan_Click(object sender, RoutedEventArgs e)
        {
            cmbFilter.IsEnabled = false;
            txtFilter.IsEnabled = false;
            btnScan.IsEnabled = false;
            btnReset.IsEnabled = false;
            btnStop.IsEnabled = true;

            trDinle = new Thread(new ThreadStart(Dinle));
            trDinle.Start();
        }

        private void btnStop_Click(object sender, RoutedEventArgs e)
        {
            btnScan.IsEnabled = true;
            btnReset.IsEnabled = true;
            btnStop.IsEnabled = false;

            trDinle.Abort();
        }

        private void btnReset_Click(object sender, RoutedEventArgs e)
        {
            cmbFilter.IsEnabled = true;
            txtFilter.IsEnabled = true;
            btnScan.IsEnabled = true;
            btnReset.IsEnabled = false;
            btnStop.IsEnabled = false;

            trDinle.Abort();
            this.dataGrid.Items.Clear();
        }

        private void dataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            System.Byte[] bytes = udp.Payload.ToArray<byte>();
            System.Byte[] TokenBytes = { };
            System.Byte[] Payloadbytes = { };
            //------------------------------------------------------
            System.Byte Ver_T_TKL = bytes[0];                                             //Ver_T_TKL,     0. byte
            System.Byte Code = bytes[1];                                                  //Code,          1. byte
            System.Byte[] MID = { bytes[2], bytes[3] };                                   //Message ID     2. 3. byte
            UInt16 MesajID = BitConverter.ToUInt16(MID, 0);                               //Tamsayıya sıfırdan başlayarak çevir
            //------------------------------------------------------
            string CoApVersiyonu = "";
            string komuttipi = "";
            if (Ver_T_TKL < 128)                                                          //ilk bit 1 değilse
            {
                CoApVersiyonu = "CoAp Versiyon 1";
                Ver_T_TKL -= 64;
            }
            //-------------------------------------------------------------------------------
            if (Ver_T_TKL >= 48) { komuttipi = "Reset"; Ver_T_TKL -= 48; }                //soldan 3 ve 4. bit 1 olmalı (00110000)
            else if (Ver_T_TKL >= 32) { komuttipi = "Acknowledgement"; Ver_T_TKL -= 32; } //3.bit
            else if (Ver_T_TKL >= 16) { komuttipi = "non-Confirmable"; Ver_T_TKL -= 16; } //4.bit
            else { komuttipi = "Confirmable"; }
            //--------------------------------------------------------------------------------
            List<byte> bytelistesiToken = new List<byte>();

            byte TokenLength = Ver_T_TKL;
            
            for (int i = 0; i < TokenLength; i++)
                try { bytelistesiToken.Add(bytes[i + 4]); }
                catch { }
            TokenBytes = bytelistesiToken.ToArray();

            List<byte> bytelistesiPayload = new List<byte>();
            for (int i = TokenLength + 5; i < bytes.Length; i++) bytelistesiPayload.Add(bytes[i]);
            Payloadbytes = bytelistesiPayload.ToArray();
            string Payload = Encoding.ASCII.GetString(Payloadbytes);                        //turn to string
            //--------------------------------------------------------------------------------

            ip = paketler[dataGrid.SelectedIndex].Ethernet.IpV4;
            udp = ip.Udp;
            tcp = ip.Tcp;
            Packet packet = paketler[dataGrid.SelectedIndex];

            treeView.Items.Clear();
            TreeViewItem treeitem1 = null;
            TreeViewItem treeitem2 = null;
            TreeViewItem treeitem3 = null;
            TreeViewItem treeitem4 = null;
            TreeViewItem treeitem5 = null;

            if (ip.Protocol.ToString() == "Udp")
            {
                treeitem1 = new TreeViewItem();
                treeitem1.Header = "Datagram";

                treeitem1.Items.Add(new TreeViewItem() { Header = "Source Port Address: " + udp.SourcePort.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Destination Port Address: " + udp.DestinationPort.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Checksum: " + udp.Checksum.ToString() });

                treeitem2 = new TreeViewItem();
                treeitem2.Header = "Ethernet";
                treeitem2.Items.Add(new TreeViewItem() { Header = "Source Mac Address: " + packet.Ethernet.Source.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Destination Mac Address: " + packet.Ethernet.Destination.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Type: " + packet.Ethernet.EtherType.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Header Length: " + packet.Ethernet.HeaderLength });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Packet Length: " + packet.Length.ToString() });

                treeitem3 = new TreeViewItem();
                treeitem3.Header = "Internet Protocol Version";
                treeitem3.Items.Add(new TreeViewItem() { Header = "Total Length: " + ip.TotalLength.ToString() });
                treeitem3.Items.Add(new TreeViewItem() { Header = "Identification: " + ip.Identification.ToString() });
                treeitem3.Items.Add(new TreeViewItem() { Header = "Header Checksum: " + ip.HeaderChecksum.ToString() });
                treeitem3.Items.Add(new TreeViewItem() { Header = "Time To Live: " + ip.Ttl.ToString() });

                treeitem4 = new TreeViewItem();
                treeitem4.Header = "Frame";
                treeitem4.Items.Add(new TreeViewItem() { Header = "Time: " + packet.Timestamp.ToString() });

                treeitem5 = new TreeViewItem();
                treeitem5.Header = "Message";
                treeitem5.Items.Add(new TreeViewItem() { Header = Payload });
            }
            else if (ip.Protocol.ToString() == "Tcp")
            {
                treeitem1 = new TreeViewItem();
                treeitem1.Header = "Transmission";
                treeitem1.Items.Add(new TreeViewItem() { Header = "Destination Port: " + tcp.DestinationPort.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Source Port: " + tcp.SourcePort.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Acknowledge: " + tcp.AcknowledgmentNumber.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Checksum: " + tcp.Checksum.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Sequence Number: " + tcp.SequenceNumber.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Window Size: " + tcp.Window.ToString() });
                treeitem1.Items.Add(new TreeViewItem() { Header = "Urgent Pointer: " + tcp.UrgentPointer.ToString() });

                treeitem2 = new TreeViewItem();
                treeitem2.Header = "Internet Protocol Version";
                treeitem2.Items.Add(new TreeViewItem() { Header = "Total Length: " + ip.TotalLength.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Identification: " + ip.Identification.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Time To Live: " + ip.Ttl.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Protocol: " + ip.Protocol.ToString() });
                treeitem2.Items.Add(new TreeViewItem() { Header = "Header Checksum: " + ip.HeaderChecksum.ToString() });

                treeitem3 = new TreeViewItem();
                treeitem3.Header = "Ethernet";
                treeitem3.Items.Add(new TreeViewItem() { Header = "Destination Mac Address: " + packet.Ethernet.Destination.ToString() });
                treeitem3.Items.Add(new TreeViewItem() { Header = "Source Mac Address: " + packet.Ethernet.Source.ToString() });
                treeitem3.Items.Add(new TreeViewItem() { Header = "Type: " + packet.Ethernet.EtherType.ToString() });

                treeitem4 = new TreeViewItem();
                treeitem4.Header = "Frame";
                treeitem4.Items.Add(new TreeViewItem() { Header = "Time: " + packet.Timestamp.ToString() });

                treeitem5 = new TreeViewItem();
                treeitem5.Header = "Message";
                treeitem5.Items.Add(new TreeViewItem() { Header = Payload });
            }
            treeView.Items.Add(treeitem1);
            treeView.Items.Add(treeitem2);
            treeView.Items.Add(treeitem3);
            treeView.Items.Add(treeitem4);
            treeView.Items.Add(treeitem5);
        }
    }
}
