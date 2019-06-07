using System;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
namespace TestTracsSmartCard
{
    class Program
    {
        static void Main(string[] args)
        {
            List<X509Certificate2> certs = TracsSmartCard.BaseSmartCardCryptoProvider.GetCertificates();
            Console.WriteLine("Hello World!");
        }
    }
}
