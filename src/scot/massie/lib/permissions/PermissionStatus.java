package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.MissingPermissionException;

import java.util.Objects;

public final class PermissionStatus
{
    private final String permission;
    private final boolean hasPermission;
    private final String permissionArg;

    PermissionStatus(String permission, boolean hasPermission, String permissionArg)
    {
        this.permission = permission;
        this.hasPermission = hasPermission;
        this.permissionArg = permissionArg;
    }

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

    @Override
    public boolean equals(Object o)
    {
        if(this == o) return true;
        if(o == null || getClass() != o.getClass()) return false;
        PermissionStatus that = (PermissionStatus)o;
        return hasPermission == that.hasPermission
            && permission.equals(that.permission)
            && Objects.equals(permissionArg, that.permissionArg);
    }

    @Override
    public int hashCode()
    { return Objects.hash(permission, hasPermission, permissionArg); }

    @Override
    public String toString()
    {
        String result = (hasPermission ? "has    : " : "has not: ") + permission;

        if(permissionArg != null)
            result += permissionArg.contains("\n") ? " - (with arg)" : ": " + permissionArg;

        return result;
    }
}