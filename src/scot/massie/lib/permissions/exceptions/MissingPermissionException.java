package scot.massie.lib.permissions.exceptions;

/**
 * Thrown when asserting that something has a permission which it does not.
 */
public class MissingPermissionException extends Exception
{
    /**
     * The permission missing.
     */
    String permissionMissing;

    /**
     * Creates a new MissingPermissionException.
     * @param permission The permission missing.
     */
    public MissingPermissionException(String permission)
    { this(permission, "Missing the permission " + permission); }

    /**
     * Creates a new MissingPermissionException.
     * @param permission The permission missing.
     * @param message The exception message.
     */
    public MissingPermissionException(String permission, String message)
    {
        super(message);
        this.permissionMissing = permission;
    }

    /**
     * Gets the permission that was missing.
     * @return The permission that was missing.
     */
    public String getPermission()
    { return permissionMissing; }
}
