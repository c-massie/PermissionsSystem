package scot.massie.lib.permissions.exceptions;

/**
 * Thrown when asserting that a group has a permission which they do not.
 */
public class GroupMissingPermissionException extends MissingPermissionException
{
    /**
     * The name of the group missing the permission.
     */
    String groupMissingPermissionName;

    /**
     * Creates a new GroupMissingPermissionException.
     * @param groupName The name of the group missing the permission.
     * @param permission The permission missing.
     */
    public GroupMissingPermissionException(String groupName, String permission)
    {
        super(permission, "The group with the name " + groupName + " was missing the permission " + permission);
        groupMissingPermissionName = groupName;
    }

    /**
     * Creates a new GroupMissingPermissionException.
     * @param groupName The name of the group missing the permission.
     * @param permission The permission missing.
     * @param message The exception message.
     */
    public GroupMissingPermissionException(String groupName, String permission, String message)
    {
        super(permission, message);
        groupMissingPermissionName = groupName;
    }

    /**
     * Gets the name of the group missing the permission.
     * @return The name of the group missing the permission.
     */
    public String getGroupName()
    { return groupMissingPermissionName; }
}
