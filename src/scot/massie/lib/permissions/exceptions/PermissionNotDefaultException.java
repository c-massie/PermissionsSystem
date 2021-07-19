package scot.massie.lib.permissions.exceptions;

/**
 * Thrown when asserting that a permission is included in the default permissions when it is not.
 */
public class PermissionNotDefaultException extends MissingPermissionException
{
    /**
     * Creates a new PermissionNotDefaultException.
     * @param permission The permission missing from the default permissions.
     */
    public PermissionNotDefaultException(String permission)
    { super(permission, "The default permissions were missing the permission " + permission); }

    /**
     * Creates a new PermissionNotDefaultException.
     * @param permission The permission missing from the default permissions.
     * @param message The exception message.
     */
    public PermissionNotDefaultException(String permission, String message)
    { super(permission, message); }
}
