using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _180202WPF_Wireshark
{
    public class Resource
    {
        public int No { get; set; }
        public string Time { get; set; }
        public string SourceIP { get; set; }
        public string DestinationIP { get; set; }
        public string TTL { get; set; }
        public string Length { get; set; }
        public string Protocol { get; set; }
    }
}
