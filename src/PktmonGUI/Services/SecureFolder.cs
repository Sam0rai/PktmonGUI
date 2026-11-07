using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PktmonGUI.Services
{
    /// <summary>
    /// Folders that elevated PktmonGUI (and SYSTEM, headless) reads, writes, deletes and runs code in.
    /// Such a folder must be owned by Administrators (or SYSTEM, TrustedInstaller), and nobody else may be
    /// able to change it or anything in it. %ProgramData% lets any user create folders, and a folder that
    /// isn't like that can't be made safe in place: its owner can always change its DACL, handles opened
    /// earlier keep their access, and whatever was put in it stays. So it's renamed aside
    /// ("&lt;name&gt;.untrusted-&lt;date&gt;", kept for inspection) and a new one is created in one step, already
    /// with its owner and protected DACL.
    /// </summary>
    internal static class SecureFolder
    {
        internal static readonly SecurityIdentifier SystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        internal static readonly SecurityIdentifier AdminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        internal static readonly SecurityIdentifier TrustedInstallerSid =
            new SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

        /// <summary>Rights that change a file or folder or what's in it (including generic write/all in inherit-only ACEs).</summary>
        private const int WriteMask =
            (int)(FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes |
                  FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.WriteAttributes | FileSystemRights.Delete |
                  FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership) |
            0x10000000 /* GENERIC_ALL */ | 0x40000000 /* GENERIC_WRITE */;

        private const int ReadMask = (int)FileSystemRights.ReadData | unchecked((int)0x80000000) /* GENERIC_READ */;

        private const int ErrorAlreadyExists = 183;

        /// <summary>
        /// SYSTEM, Administrators and TrustedInstaller; plus <paramref name="owner"/>, which is Administrators
        /// except in tests (they can't create folders owned by Administrators unelevated).
        /// </summary>
        internal static bool IsTrusted(SecurityIdentifier sid, SecurityIdentifier owner) =>
            sid != null && (sid == SystemSid || sid == AdminsSid || sid == TrustedInstallerSid || sid == owner);

        /// <summary>
        /// Makes <paramref name="path"/> a safe folder: creates it if missing; if it, or anything in it,
        /// isn't safe, renames it aside and creates it again. <paramref name="setAside"/> says what was set
        /// aside and why, for the caller to report. <paramref name="reader"/> (the GUI's user) gets read
        /// access, so Explorer can open the folder without offering to "permanently get access", which
        /// would grant that user full control. Returns why no safe folder could be made, or null.
        /// </summary>
        public static string Ensure(string path, out string setAside, SecurityIdentifier reader = null, bool readerInherits = false) =>
            Ensure(path, out setAside, reader, readerInherits, AdminsSid);

        internal static string Ensure(string path, out string setAside, SecurityIdentifier reader, bool readerInherits, SecurityIdentifier owner)
        {
            setAside = null;
            path = path.TrimEnd('\\');
            try
            {
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    if (!TryGetAttributes(path, out _))
                    {
                        int error = Create(path, NewSecurity(owner, reader, readerInherits));
                        if (error == 0) return null;
                        if (error != ErrorAlreadyExists) return $"Couldn't create {path}: {new Win32Exception(error).Message}";
                        continue; // someone created it meanwhile: inspect theirs
                    }

                    var problem = Inspect(path, owner);
                    if (problem == null)
                    {
                        if (reader != null) AddReader(path, reader, readerInherits);
                        return null;
                    }

                    string aside;
                    try { aside = MoveAside(path); }
                    catch (Exception ex) { return $"{problem} It couldn't be set aside ({ex.Message}). Delete {path} and run again."; }
                    setAside = (setAside == null ? "" : setAside + " ") + $"{problem} It was set aside as {aside} and {path} was made again.";
                }
                return $"{path} kept being recreated by someone else, so it couldn't be made safe.";
            }
            catch (Exception ex) { return $"Couldn't prepare {path}: {ex.Message}"; }
        }

        /// <summary>
        /// Why the folder itself isn't safe (its contents aren't looked at), or null, also when it doesn't
        /// exist yet. Changes nothing; for showing ahead of time, e.g. in Preflight.
        /// </summary>
        public static string Check(string path) => Check(path, AdminsSid);

        internal static string Check(string path, SecurityIdentifier owner)
        {
            try
            {
                path = path.TrimEnd('\\');
                if (!TryGetAttributes(path, out var attrs)) return null;
                var shape = Shape(path, attrs);
                if (shape != null) return shape;
                return Evaluate(path, Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access), owner);
            }
            catch (Exception ex) { return $"Couldn't check {path}: {ex.Message}"; }
        }

        /// <summary>
        /// For a folder the operator named (--out, a local --collect, the --log folder): why another account
        /// could change it, or null (also when it doesn't exist). Unlike <see cref="Check(string)"/> it may
        /// also belong to the account running this: an administrator owns what it creates on client Windows.
        /// </summary>
        public static string CheckOperatorFolder(string path)
        {
            SecurityIdentifier me;
            try { using (var id = WindowsIdentity.GetCurrent()) me = id.User; } catch { me = AdminsSid; }
            return Check(path, me);
        }

        /// <summary>
        /// Creates a new file that only SYSTEM and Administrators (and <paramref name="alsoAllow"/>, for
        /// tests) can open. Fails if anything is already there, a link included, so nothing is overwritten
        /// or followed.
        /// </summary>
        public static FileStream CreateNewFile(string path, SecurityIdentifier alsoAllow = null)
        {
            var sec = new FileSecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in alsoAllow == null ? new[] { SystemSid, AdminsSid } : new[] { SystemSid, AdminsSid, alsoAllow })
                sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
            return new FileStream(path, FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write, FileShare.None,
                                  1 << 16, FileOptions.None, sec);
        }

        /// <summary>The folder, then everything in it. Children owned by another account get Administrators as owner.</summary>
        private static string Inspect(string path, SecurityIdentifier owner)
        {
            var problem = Check(path, owner);
            if (problem != null) return problem;
            // Something Administrators can't even look at (e.g. a deny rule) is as suspect as a loose ACL.
            try { return InspectChildren(path, owner); }
            catch (Exception ex) { return $"What's in {path} couldn't be checked ({ex.Message})."; }
        }

        /// <summary>
        /// A link, or something another account can change, means someone tampered with the folder: the
        /// whole folder is set aside. A child that's only owned by another account is normal on client
        /// Windows (an admin owns what it creates elevated): Administrators becomes its owner, so that
        /// account's unelevated processes can't change its ACL. If that fails, the folder is set aside too.
        /// </summary>
        private static string InspectChildren(string folder, SecurityIdentifier owner)
        {
            var pending = new Stack<string>();
            pending.Push(folder);
            while (pending.Count > 0)
            {
                foreach (var entry in Directory.GetFileSystemEntries(pending.Pop()))
                {
                    var attrs = File.GetAttributes(entry);
                    if ((attrs & FileAttributes.ReparsePoint) != 0) return $"{entry} is a link.";
                    bool isDir = (attrs & FileAttributes.Directory) != 0;
                    FileSystemSecurity sec = isDir
                        ? (FileSystemSecurity)Directory.GetAccessControl(entry, AccessControlSections.Owner | AccessControlSections.Access)
                        : File.GetAccessControl(entry, AccessControlSections.Owner | AccessControlSections.Access);
                    var writer = UntrustedWriter(sec, owner);
                    if (writer != null) return $"{entry} lets {Describe(writer)} change it.";
                    if (!IsTrusted(sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier, owner))
                    {
                        try { SetOwner(entry, isDir, owner); }
                        catch (Exception ex) { return $"{entry} belongs to another account, and Administrators couldn't be made its owner ({ex.Message})."; }
                    }
                    if (isDir) pending.Push(entry);
                }
            }
            return null;
        }

        private static string Shape(string path, FileAttributes attrs)
        {
            if ((attrs & FileAttributes.ReparsePoint) != 0) return $"{path} is a link, not a folder.";
            if ((attrs & FileAttributes.Directory) == 0) return $"{path} is a file, not a folder.";
            return null;
        }

        /// <summary>The ownership and DACL rules for the folder itself, on a security descriptor already read.</summary>
        internal static string Evaluate(string path, DirectorySecurity sec, SecurityIdentifier owner = null)
        {
            owner = owner ?? AdminsSid;
            var actual = sec.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!IsTrusted(actual, owner))
                return $"{path} belongs to {Describe(actual)}, not to Administrators.";
            var writer = UntrustedWriter(sec, owner);
            return writer == null ? null : $"{path} lets {Describe(writer)} change what's in it.";
        }

        /// <summary>
        /// The first account outside SYSTEM, Administrators and TrustedInstaller an allow rule lets change
        /// the object, or null. CREATOR OWNER is skipped: it grants rights only over items a principal itself
        /// creates, so it's inert unless some other ACE lets that principal create here (which this would then
        /// catch). Program Files carries it by default, and is trusted.
        /// </summary>
        internal static SecurityIdentifier UntrustedWriter(FileSystemSecurity sec, SecurityIdentifier owner)
        {
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                var sid = (SecurityIdentifier)rule.IdentityReference;
                if (sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid)) continue;
                if (!IsTrusted(sid, owner) && ((int)rule.FileSystemRights & WriteMask) != 0) return sid;
            }
            return null;
        }

        /// <summary>
        /// For a folder the user picked: who besides SYSTEM, Administrators and the user can change or read
        /// the captures there. A warning, not a refusal. Null when nobody else can, or it can't be read.
        /// </summary>
        public static string Exposure(string path, SecurityIdentifier user)
        {
            try
            {
                if (!Directory.Exists(path)) return null;
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return "it's a link to another folder";
                return EvaluateExposure(Directory.GetAccessControl(path, AccessControlSections.Access), user);
            }
            catch { return null; }
        }

        internal static string EvaluateExposure(DirectorySecurity sec, SecurityIdentifier user)
        {
            string readers = null;
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                var sid = (SecurityIdentifier)rule.IdentityReference;
                if (IsTrusted(sid, AdminsSid) || sid == user || sid.IsWellKnown(WellKnownSidType.CreatorOwnerSid)) continue;
                int rights = (int)rule.FileSystemRights;
                if ((rights & WriteMask) != 0) return $"{Describe(sid)} can change files here";
                if ((rights & ReadMask) != 0 && readers == null) readers = $"{Describe(sid)} can read the captures here";
            }
            return readers;
        }

        // ---- Creating, setting aside --------------------------------------------------------

        private static DirectorySecurity NewSecurity(SecurityIdentifier owner, SecurityIdentifier reader, bool readerInherits)
        {
            var sec = new DirectorySecurity();
            sec.SetOwner(owner);
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in owner == AdminsSid ? new[] { SystemSid, AdminsSid } : new[] { SystemSid, AdminsSid, owner })
                sec.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            if (reader != null) sec.AddAccessRule(ReaderRule(reader, readerInherits));
            return sec;
        }

        /// <summary>
        /// CreateDirectory with the security descriptor, failing if the path exists (Directory.CreateDirectory
        /// would accept someone else's folder). Returns the Win32 error, 0 on success.
        /// </summary>
        private static int Create(string path, DirectorySecurity sec)
        {
            var sd = sec.GetSecurityDescriptorBinaryForm();
            var pin = GCHandle.Alloc(sd, GCHandleType.Pinned);
            try
            {
                var sa = new SECURITY_ATTRIBUTES
                {
                    nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
                    lpSecurityDescriptor = pin.AddrOfPinnedObject(),
                };
                return CreateDirectoryW(path, ref sa) ? 0 : Marshal.GetLastWin32Error();
            }
            finally { pin.Free(); }
        }

        /// <summary>Renames <paramref name="path"/> (a folder, a link or a file) to "&lt;name&gt;.untrusted-&lt;date&gt;" beside it.</summary>
        private static string MoveAside(string path)
        {
            var parent = Path.GetDirectoryName(path);
            var baseName = Path.GetFileName(path) + ".untrusted-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            var aside = Path.Combine(parent, baseName);
            for (int n = 2; TryGetAttributes(aside, out _); n++) aside = Path.Combine(parent, baseName + "-" + n);
            TryGetAttributes(path, out var attrs);
            // A link is renamed itself, not followed.
            if ((attrs & FileAttributes.Directory) != 0) Directory.Move(path, aside);
            else File.Move(path, aside);
            return aside;
        }

        private static void SetOwner(string path, bool isDir, SecurityIdentifier owner)
        {
            // Only the owner section is written.
            if (isDir) { var d = new DirectorySecurity(); d.SetOwner(owner); Directory.SetAccessControl(path, d); }
            else { var f = new FileSecurity(); f.SetOwner(owner); File.SetAccessControl(path, f); }
        }

        private static FileSystemAccessRule ReaderRule(SecurityIdentifier reader, bool inherits) =>
            new FileSystemAccessRule(reader, FileSystemRights.ReadAndExecute,
                inherits ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
                PropagationFlags.None, AccessControlType.Allow);

        /// <summary>Adds the read-only rule unless it's there already; a convenience, so failure is ignored.</summary>
        private static void AddReader(string path, SecurityIdentifier reader, bool inherits)
        {
            try
            {
                var sec = Directory.GetAccessControl(path, AccessControlSections.Access);
                var before = sec.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
                sec.AddAccessRule(ReaderRule(reader, inherits));
                if (sec.GetSecurityDescriptorSddlForm(AccessControlSections.Access) != before)
                    Directory.SetAccessControl(path, sec);
            }
            catch { }
        }

        /// <summary>Attributes of the path itself (a link isn't followed); false if nothing is there, not even a dangling link.</summary>
        private static bool TryGetAttributes(string path, out FileAttributes attrs)
        {
            try { attrs = File.GetAttributes(path); return true; }
            catch (FileNotFoundException) { attrs = 0; return false; }
            catch (DirectoryNotFoundException) { attrs = 0; return false; }
        }

        internal static string Describe(SecurityIdentifier sid)
        {
            if (sid == null) return "an unknown account";
            try { return sid.Translate(typeof(NTAccount)).Value; } catch { return sid.Value; }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(string lpPathName, ref SECURITY_ATTRIBUTES lpSecurityAttributes);
    }
}
