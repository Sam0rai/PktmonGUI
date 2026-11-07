using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Keeps Windows from sleeping when idle while a capture records: nobody may be at the keyboard
    /// (a remote host, or a long capture left running), and a capture doesn't survive the machine
    /// going to sleep. Shown by <c>powercfg /requests</c>. Sleep that someone asks for (Start menu,
    /// lid) still happens.
    /// </summary>
    internal sealed class KeepAwake : IDisposable
    {
        private readonly SafeFileHandle _request;

        private KeepAwake(SafeFileHandle request) { _request = request; }

        /// <summary>Null if Windows refused; <paramref name="error"/> says why.</summary>
        public static KeepAwake Start(string reason, out string error)
        {
            error = null;
            var context = new REASON_CONTEXT
            {
                Version = POWER_REQUEST_CONTEXT_VERSION,
                Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING,
                SimpleReasonString = reason,
            };
            var request = PowerCreateRequest(ref context);
            if (request.IsInvalid)
            {
                error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                return null;
            }
            if (!PowerSetRequest(request, PowerRequestSystemRequired))
            {
                error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                request.Dispose();
                return null;
            }
            return new KeepAwake(request);
        }

        public void Dispose()
        {
            if (_request.IsClosed) return;
            PowerClearRequest(_request, PowerRequestSystemRequired);
            _request.Dispose();
        }

        private const uint POWER_REQUEST_CONTEXT_VERSION = 0;
        private const uint POWER_REQUEST_CONTEXT_SIMPLE_STRING = 1;
        private const int PowerRequestSystemRequired = 1;

        /// <summary>REASON_CONTEXT with the simple-string member of its union.</summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct REASON_CONTEXT
        {
            public uint Version;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPWStr)] public string SimpleReasonString;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle PowerCreateRequest(ref REASON_CONTEXT context);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PowerSetRequest(SafeFileHandle powerRequest, int requestType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PowerClearRequest(SafeFileHandle powerRequest, int requestType);
    }
}
