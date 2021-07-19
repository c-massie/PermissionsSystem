package scot.massie.lib.permissions.exceptions;

/**
 * Thrown when asserting that a user has a permission which they do not.
 */
public class UserMissingPermissionException extends MissingPermissionException
{
    /**
     * The ID of the user missing the permission.
     */
    Comparable userMissingPermissionId;

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permission.
     * @param permission The permission missing.
     */
    public UserMissingPermissionException(Comparable userId, String permission)
    {
        super(permission, "The user with the ID " + userId.toString() + " was missing the permission " + permission);
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permission.
     * @param permission The permission missing.
     * @param message The exception message.
     */
    public UserMissingPermissionException(Comparable userId, String permission, String message)
    {
        super(permission, message);
        userMissingPermissionId = userId;
    }

    /**
     * Gets the ID of the user missing the permission.
     * @return The ID of the user missing the permission.
     */
    public Comparable getUserId()
    { return userMissingPermissionId; }
}
