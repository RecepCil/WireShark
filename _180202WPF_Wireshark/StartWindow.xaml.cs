using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace _180202WPF_Wireshark
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class StartWindow : Window
    {
        static IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
        static PacketDevice selectedDevice = allDevices[0];
        public int deviceIndex = 0;
   

        public StartWindow()
        {
            InitializeComponent();

            //If there is no device
            if (allDevices.Count == 0)
            {
                cmbNetworkDevice.Items.Add("No interfaces found! Make sure WinPcap is installed.");
                return;
            }
       
            //Get devices name to combobox
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
       
                if (device.Description != null)
                    cmbNetworkDevice.Items.Add((i + 1) + ". " + "(" + device.Description + ")");
                else
                    cmbNetworkDevice.Items.Add((i + 1) + ". " + "( Açıklama Yok )");
            }

        }

        private void cmbNetworkDevice_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            button.Visibility = Visibility.Visible;

            deviceIndex = cmbNetworkDevice.SelectedIndex;
            selectedDevice = allDevices[deviceIndex];
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            MainWindow mainwindow = new MainWindow(deviceIndex);
            this.Hide();
            mainwindow.Show();
        }
    }
}
