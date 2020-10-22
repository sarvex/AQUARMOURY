// based on https://github.com/zodiacon/DotNextSP2019/blob/master/SimpleConsumer/Program.cs
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace PPIDSpoofingDetection
{
    static class Program
    {
        static void Main(string[] args)
        {
            using (var session = new TraceEventSession("spotless-ppid-spoofing"))
            {
                Console.CancelKeyPress += delegate {
                    session.Source.StopProcessing();
                    session.Dispose();
                };

                session.EnableProvider("Microsoft-Windows-Kernel-Process", Microsoft.Diagnostics.Tracing.TraceEventLevel.Always, 0x10);
                var parser = session.Source.Dynamic;
                parser.All += e => {
                    if (e.OpcodeName == "Start" && Regex.IsMatch(e.FormattedMessage.ToLower(), "werfault") == false)
                    {
                        string[] messageBits = e.FormattedMessage.Replace(",", string.Empty).Split(' ');
                        int PID = int.Parse(messageBits[1]);
                        int PPID = int.Parse(messageBits[10]);
                        int realPPID = e.ProcessID;

                        if (PPID != realPPID)
                        {
                            // this may fail if the process is already gone.
                            string processName = Process.GetProcessById(PID).ProcessName;
                            Console.WriteLine($"{e.TimeStamp} PPID Spoofing detected: {processName} (PID={PID}) started by PPID={realPPID} rather than PPID={PPID}");
                        }
                    }
                };
                session.Source.Process();
            }
        }
    }
}