package scot.massie.lib.permissions;

public final class PermissionStatus
{
    PermissionStatus(String permission, boolean hasPermission, String permissionArg)
    {
        this.permission = permission;
        this.hasPermission = hasPermission;
        this.permissionArg = permissionArg;
    }

    private final String permission;
    private final boolean hasPermission;
    private final String permissionArg;

    public String getPermission()
    { return permission; }

    public boolean hasPermission()
    { return hasPermission; }

    public String getPermissionArg()
    { return permissionArg; }
}