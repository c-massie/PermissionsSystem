package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.MissingPermissionException;

import java.util.Objects;

/**
 * A permission's path, paired with whether or not the permission was present
 */
public final class PermissionStatus
{
    /**
     * The permission's path.
     */
    private final String permission;

    /**
     * Whether or not whatever this represents the status of had the given permission.
     */
    private final boolean hasPermission;

    /**
     * The permission argument. If the permission has no argument, this will be null.
     */
    private final String permissionArg;

    /**
     * Wraps a permission, whether or not the permission is present, and the permission arg if applicable.
     * @param permission The permission path.
     * @param hasPermission Whether or not the target has the given permission.
     * @param permissionArg The argument of the permission, if applicable. Null should be passed if the permission has
     *                      no argument.
     */
    public PermissionStatus(String permission, boolean hasPermission, String permissionArg)
    {
        this.permission = permission;
        this.hasPermission = hasPermission;
        this.permissionArg = permissionArg;
    }

    /**
     * Wraps a permission and whether or not the permission is present.
     * @param permission The permission path.
     * @param hasPermission Whether or not the target has the given permission.
     */
    public PermissionStatus(String permission, boolean hasPermission)
    { this(permission, hasPermission, null); }

    /**
     * Gets the permission path this represents.
     * @return The permission path.
     */
    public String getPermission()
    { return permission; }

    /**
     * Whether or not the permission this represents was present.
     * @return True if the permission was present, otherwise false.
     */
    public boolean hasPermission()
    { return hasPermission; }

    /**
     * Asserts that the permission this represents was present.
     * @throws MissingPermissionException If the permission was not present.
     */
    public void assertHasPermission() throws MissingPermissionException
    {
        if(!hasPermission)
            throw new MissingPermissionException(permission);
    }

    /**
     * Gets the permission argument.
     * @return The permission argument if there is one. Otherwise, null.
     */
    public String getPermissionArg()
    { return permissionArg; }

    /**
     * Whether or not the permission has an associated argument.
     * @return True if there is a permission argument associated with the permission. Otherwise, false.
     */
    public boolean hasPermissionArg()
    { return permissionArg != null; }

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