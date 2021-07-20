package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.MissingPermissionException;

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

    public void assertHasPermission() throws MissingPermissionException
    {
        if(!hasPermission)
            throw new MissingPermissionException(permission);
    }

    public String getPermissionArg()
    { return permissionArg; }
}