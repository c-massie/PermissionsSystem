package scot.massie.lib.permissions.exceptions;

import java.util.Collection;
import java.util.Collections;

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
        super(permission, getDefaultMessage(groupName, Collections.singletonList(permission)));
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
     * Creates a new GroupMissingPermissionException
     * @param groupName The name of the group missing the permissions.
     * @param permissions The permissions missing.
     */
    public GroupMissingPermissionException(String groupName, Iterable<String> permissions)
    {
        super(permissions, getDefaultMessage(groupName, permissions));
        groupMissingPermissionName = groupName;
    }

    /**
     * Creates a new GroupMissingPermissionException
     * @param groupName The name of the group missing the permissions.
     * @param permissions The permissions missing.
     * @param message The exception message.
     */
    public GroupMissingPermissionException(String groupName, Iterable<String> permissions, String message)
    {
        super(permissions, message);
        groupMissingPermissionName = groupName;
    }

    /**
     * Creates a new GroupMissingPermissionException
     * @param groupName The name of the group missing the permissions.
     * @param permissions The permissions missing.
     */
    public GroupMissingPermissionException(String groupName, Collection<String> permissions)
    {
        super(permissions, getDefaultMessage(groupName, permissions));
        groupMissingPermissionName = groupName;
    }

    /**
     * Creates a new GroupMissingPermissionException
     * @param groupName The name of the group missing the permissions.
     * @param permissions The permissions missing.
     * @param message The exception message.
     */
    public GroupMissingPermissionException(String groupName, Collection<String> permissions, String message)
    {
        super(permissions, message);
        groupMissingPermissionName = groupName;
    }

    /**
     * Gets the default exception message for a given iterable of permissions.
     * @param permissions The permissions to get the default exception message for.
     * @return The default exception message.
     */
    private static String getDefaultMessage(String groupName, Iterable<String> permissions)
    {
        int permissionCount = 0;
        StringBuilder resultBuilder = new StringBuilder();
        String linePrefix = "  - ";

        for(String p : permissions)
        {
            resultBuilder.append("\n").append(linePrefix).append(p);
            permissionCount++;
        }

        String result;

        if(permissionCount == 1)
        {
            result = "The group with the name " + groupName + "was missing the permission "
                     + resultBuilder.substring(linePrefix.length() + 1);
        }
        else
        { result = "The group with the name " + groupName + "was missing the permissions: " + resultBuilder; }

        return result;
    }

    /**
     * Gets the default exception message for a given collection of permissions.
     * @param permissions The permissions to get the default exception message for.
     * @return The default exception message.
     */
    private static String getDefaultMessage(String groupName, Collection<String> permissions)
    {
        if(permissions.size() != 1)
        {
            //noinspection OptionalGetWithoutIsPresent
            return "The group with the name " + groupName + " was missing the permission "
                   + permissions.stream().findFirst().get();
        }

        StringBuilder resultBuilder = new StringBuilder();
        String linePrefix = "  - ";

        for(String p : permissions)
            resultBuilder.append("\n").append(linePrefix).append(p);

        return "The group with the name " + groupName + " was missing the permissions: " + resultBuilder;
    }

    /**
     * Gets the name of the group missing the permission.
     * @return The name of the group missing the permission.
     */
    public String getGroupName()
    { return groupMissingPermissionName; }
}
