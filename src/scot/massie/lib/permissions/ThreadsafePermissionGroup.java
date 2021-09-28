package scot.massie.lib.permissions;

public class ThreadsafePermissionGroup extends PermissionGroup
{
    public ThreadsafePermissionGroup(String name)
    { super(name); }

    public ThreadsafePermissionGroup(String name, long priority)
    { super(name, priority); }

    public ThreadsafePermissionGroup(String name, double priority)
    { super(name, priority); }

    public ThreadsafePermissionGroup(String name, PermissionGroup defaultPermissions)
    { super(name, defaultPermissions); }

    public ThreadsafePermissionGroup(String name, PermissionGroup defaultPermissions, long priority)
    { super(name, defaultPermissions, priority); }

    public ThreadsafePermissionGroup(String name, PermissionGroup defaultPermissions, double priority)
    { super(name, defaultPermissions, priority); }
}
