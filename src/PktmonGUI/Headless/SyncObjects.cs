using System;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using PktmonGUI.Services;

namespace PktmonGUI.Headless
{
    /// <summary>A headless named object exists, but SYSTEM or Administrators didn't create it.</summary>
    internal sealed class ForeignObjectException : Exception
    {
        public ForeignObjectException(string message) : base(message) { }
    }

    /// <summary>
    /// The machine-wide objects headless mode coordinates through. Both carry an explicit ACL: by
    /// default an object SYSTEM creates only lets Administrators wait on it, so an admin's --stop
    /// couldn't signal a capture a SYSTEM task started.
    /// </summary>
    /// <remarks>
    /// Any user may create mutexes and events in Global\, so someone could create these first: holding
    /// the mutex would block every capture, and setting their own stop event would end one. PktmonGUI
    /// makes Administrators the owner of the objects it creates (a standard user can't), and uses an
    /// existing object only if SYSTEM or Administrators owns it. Otherwise the command fails with
    /// <see cref="ForeignObjectException"/>.
    /// </remarks>
    internal static class SyncObjects
    {
        /// <summary>Held by the one running headless capture.</summary>
        public const string MutexName = @"Global\PktmonGUI-Headless";
        /// <summary>Set by --stop; exists only while a capture runs.</summary>
        public const string StopEventName = @"Global\PktmonGUI-Headless-Stop";

        private static SecurityIdentifier[] Owners => new[] { SecureFolder.SystemSid, SecureFolder.AdminsSid };

        public static Mutex CreateMutex() => CreateMutex(MutexName);

        internal static Mutex CreateMutex(string name)
        {
            var sec = new MutexSecurity();
            sec.SetOwner(SecureFolder.AdminsSid);
            foreach (var sid in Owners) sec.AddAccessRule(new MutexAccessRule(sid, MutexRights.FullControl, AccessControlType.Allow));
            Mutex m;
            bool created;
            try { m = new Mutex(false, name, out created, sec); }
            catch (UnauthorizedAccessException) { throw Foreign(name, null); } // ours always lets Administrators in
            if (!created) Verify(m, m.GetAccessControl(), name);
            return m;
        }

        public static EventWaitHandle CreateStopEvent() => CreateStopEvent(StopEventName);

        internal static EventWaitHandle CreateStopEvent(string name)
        {
            var sec = new EventWaitHandleSecurity();
            sec.SetOwner(SecureFolder.AdminsSid);
            foreach (var sid in Owners) sec.AddAccessRule(new EventWaitHandleAccessRule(sid, EventWaitHandleRights.FullControl, AccessControlType.Allow));
            EventWaitHandle ev;
            bool created;
            try { ev = new EventWaitHandle(false, EventResetMode.ManualReset, name, out created, sec); }
            catch (UnauthorizedAccessException) { throw Foreign(name, null); }
            // An existing one of ours is a --stop that hasn't closed its handle yet; someone else's is refused.
            if (!created) Verify(ev, ev.GetAccessControl(), name);
            ev.Reset();
            return ev;
        }

        /// <summary>The running capture's stop event, or null if no headless capture is running.</summary>
        public static EventWaitHandle TryOpenStopEvent() => TryOpenStopEvent(StopEventName);

        internal static EventWaitHandle TryOpenStopEvent(string name)
        {
            EventWaitHandle ev;
            try
            {
                if (!EventWaitHandle.TryOpenExisting(name,
                        EventWaitHandleRights.Modify | EventWaitHandleRights.Synchronize | EventWaitHandleRights.ReadPermissions, out ev))
                    return null;
            }
            catch (UnauthorizedAccessException) when (SystemChecks.IsAdministrator()) { throw Foreign(name, null); }
            Verify(ev, ev.GetAccessControl(), name);
            return ev;
        }

        /// <summary>True while another process holds the headless mutex, i.e. a capture is running.</summary>
        public static bool IsMutexHeld() => IsMutexHeld(MutexName);

        internal static bool IsMutexHeld(string name)
        {
            Mutex m;
            try
            {
                if (!Mutex.TryOpenExisting(name, MutexRights.Synchronize | MutexRights.Modify | MutexRights.ReadPermissions, out m)) return false;
            }
            catch (UnauthorizedAccessException) when (SystemChecks.IsAdministrator()) { throw Foreign(name, null); }
            using (m)
            {
                Verify(m, m.GetAccessControl(), name);
                try
                {
                    if (!m.WaitOne(0)) return true;
                    m.ReleaseMutex();
                    return false;
                }
                catch (AbandonedMutexException)
                {
                    // Its owner died; we own it now.
                    try { m.ReleaseMutex(); } catch { }
                    return false;
                }
            }
        }

        /// <summary>Closes <paramref name="handle"/> and throws unless SYSTEM or Administrators owns the object.</summary>
        private static void Verify(WaitHandle handle, NativeObjectSecurity sec, string name)
        {
            var owner = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (IsOurs(owner)) return;
            handle.Dispose();
            throw Foreign(name, owner);
        }

        internal static bool IsOurs(SecurityIdentifier owner) => owner == SecureFolder.SystemSid || owner == SecureFolder.AdminsSid;

        private static ForeignObjectException Foreign(string name, SecurityIdentifier owner) =>
            new ForeignObjectException(
                $"{name} already exists, " + (owner != null ? $"created by {SecureFolder.Describe(owner)}" : "and Administrators can't use it") +
                ": it isn't PktmonGUI's, and whoever holds it could block or stop headless captures. " +
                "End the process that holds it (Process Explorer's Find Handle shows which), then run again.");
    }
}
