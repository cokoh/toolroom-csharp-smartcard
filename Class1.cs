using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace TracsSmartCard
{
    public static class BaseSmartCardCryptoProvider
    {
        // - names https://docs.microsoft.com/en-us/windows/desktop/seccrypto/cryptographic-provider-names
        private const string _providerName = "Microsoft Base Smart Card Crypto Provider";

        private static class NativeMethods
        {
            public const uint PROV_RSA_FULL = 0x00000001;
            public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
            public const uint CRYPT_FIRST = 0x00000001;
            public const uint CRYPT_NEXT = 0x00000002;
            public const uint ERROR_NO_MORE_ITEMS = 0x00000103;
            public const uint PP_ENUMCONTAINERS = 0x00000002;

            [DllImport("advapi32.dll", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
            public static extern bool CryptAcquireContext(
            ref IntPtr phProv,
            [MarshalAs(UnmanagedType.LPStr)] string pszContainer,
            [MarshalAs(UnmanagedType.LPStr)] string pszProvider,
            uint dwProvType,
            uint dwFlags);

            [DllImport("advapi32.dll", BestFitMapping = false, ThrowOnUnmappableChar = true, SetLastError = true)]
            public static extern bool CryptGetProvParam(
            IntPtr hProv,
            uint dwParam,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData,
            ref uint pdwDataLen,
            uint dwFlags);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool CryptReleaseContext(
            IntPtr hProv,
            uint dwFlags);
        }

        public static List<X509Certificate2> GetCertificates()
        {
            List<X509Certificate2> certs = new List<X509Certificate2>();

            X509Store x509Store = null;

            try
            {
                x509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                x509Store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                List<string> containers = GetKeyContainers();

                foreach (string container in containers)
                {
                    CspParameters cspParameters = new CspParameters((int)NativeMethods.PROV_RSA_FULL, _providerName, container);
                    cspParameters.Flags = CspProviderFlags.UseExistingKey;
                    string pubKeyXml = null;
                    using (RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParameters))
                        pubKeyXml=ToXmlString(rsaProvider, false);//pubKeyXml = rsaProvider.ToXmlString(false);

                    foreach (X509Certificate2 cert in x509Store.Certificates)
                    {
                       // if ((cert.PublicKey.Key.ToXmlString(false) == pubKeyXml) && cert.HasPrivateKey)
                       if(cert.HasPrivateKey)
                            certs.Add(cert);
                    }
                }
            }
            finally
            {
                if (x509Store != null)
                {
                    x509Store.Close();
                    x509Store = null;
                }
            }

            return certs;
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }

        private static List<string> GetKeyContainers()
        {
            List<string> containers = new List<string>();

            IntPtr hProv = IntPtr.Zero;

            try
            {
                if (!NativeMethods.CryptAcquireContext(ref hProv, null, _providerName, NativeMethods.PROV_RSA_FULL, NativeMethods.CRYPT_VERIFYCONTEXT))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                uint pcbData = 0;
                uint dwFlags = NativeMethods.CRYPT_FIRST;
                if (!NativeMethods.CryptGetProvParam(hProv, NativeMethods.PP_ENUMCONTAINERS, null, ref pcbData, dwFlags))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                StringBuilder sb = new StringBuilder((int)pcbData + 1);
                while (NativeMethods.CryptGetProvParam(hProv, NativeMethods.PP_ENUMCONTAINERS, sb, ref pcbData, dwFlags))
                {
                    containers.Add(sb.ToString());
                    dwFlags = NativeMethods.CRYPT_NEXT;
                }

                int err = Marshal.GetLastWin32Error();
                if (err != NativeMethods.ERROR_NO_MORE_ITEMS)
                    throw new Win32Exception(err);

                if (hProv != IntPtr.Zero)
                {
                    if (!NativeMethods.CryptReleaseContext(hProv, 0))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    hProv = IntPtr.Zero;
                }
            }
            catch
            {
                if (hProv != IntPtr.Zero)
                {
                    if (!NativeMethods.CryptReleaseContext(hProv, 0))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    hProv = IntPtr.Zero;
                }

                throw;
            }

            return containers;
        }
    }
}