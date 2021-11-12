package scot.massie.lib.permissions.exceptions;

import java.util.Collection;
import java.util.Collections;

/**
 * Thrown when asserting that a permission is included in the default permissions when it is not.
 */
public class PermissionNotDefaultException extends MissingPermissionException
{
    /**
     * Creates a new PermissionNotDefaultException
     * @param permission The permission that's not default.
     */
    public PermissionNotDefaultException(String permission)
    { super(permission, getDefaultMessage(Collections.singletonList(permission))); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permission The permission that's not default.
     * @param message The exception message.
     */
    public PermissionNotDefaultException(String permission, String message)
    { super(permission, message); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     */
    public PermissionNotDefaultException(Iterable<String> permissions)
    { super(permissions, getDefaultMessage(permissions)); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     * @param message The exception message.
     */
    public PermissionNotDefaultException(Iterable<String> permissions, String message)
    { super(permissions, message); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     */
    public PermissionNotDefaultException(Collection<String> permissions)
    { super(permissions, getDefaultMessage(permissions)); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     * @param message The exception message.
     */
    public PermissionNotDefaultException(Collection<String> permissions, String message)
    { super(permissions, message); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public PermissionNotDefaultException(Iterable<String> permissions, boolean isForAnyPermissions)
    { super(permissions, getDefaultMessage(permissions), isForAnyPermissions); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     * @param message The exception message.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public PermissionNotDefaultException(Iterable<String> permissions, String message, boolean isForAnyPermissions)
    { super(permissions, message, isForAnyPermissions); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public PermissionNotDefaultException(Collection<String> permissions, boolean isForAnyPermissions)
    { super(permissions, getDefaultMessage(permissions), isForAnyPermissions); }

    /**
     * Creates a new PermissionNotDefaultException
     * @param permissions The permissions that are not default.
     * @param message The exception message.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public PermissionNotDefaultException(Collection<String> permissions, String message, boolean isForAnyPermissions)
    { super(permissions, message, isForAnyPermissions); }

    /**
     * Gets the default exception message for a given iterable of permissions.
     * @param permissions The permissions to get the default exception message for.
     * @return The default exception message.
     */
    private static String getDefaultMessage(Iterable<String> permissions)
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
            result = "The default permissions were missing the permission "
                     + resultBuilder.substring(linePrefix.length() + 1);
        }
        else
            result = "The default permissions were missing the permissions: " + resultBuilder;

        return result;
    }

    /**
     * Gets the default exception message for a given collection of permissions.
     * @param permissions The permissions to get the default exception message for.
     * @return The default exception message.
     */
    private static String getDefaultMessage(Collection<String> permissions)
    {
        if(permissions.size() != 1)
        {
            //noinspection OptionalGetWithoutIsPresent
            return "The default permissions were missing the permission " + permissions.stream().findFirst().get();
        }

        StringBuilder resultBuilder = new StringBuilder();
        String linePrefix = "  - ";

        for(String p : permissions)
            resultBuilder.append("\n").append(linePrefix).append(p);

        return "The default permissions were missing the permissions: " + resultBuilder;
    }
}
