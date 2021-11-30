package scot.massie.lib.permissions.exceptions;

import java.util.Collection;
import java.util.Collections;

/**
 * Thrown when asserting that a user has a permission which they do not.
 */
@SuppressWarnings("rawtypes") // As this is an exception, I can't be more specific about the ID of the user.
public class UserMissingPermissionException extends MissingPermissionException
{
    //region Instance fields
    /**
     * The ID of the user missing the permission.
     */
    Comparable userMissingPermissionId;
    //endregion

    //region Initialisation
    //region Constructors
    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permission.
     * @param permission The permission missing.
     */
    public UserMissingPermissionException(Comparable userId, String permission)
    {
        super(permission, getDefaultMessage(userId, Collections.singletonList(permission)));
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
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     */
    public UserMissingPermissionException(Comparable userId, Iterable<String> permissions)
    {
        super(permissions, getDefaultMessage(userId, permissions));
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     * @param message The exception message.
     */
    public UserMissingPermissionException(Comparable userId, Iterable<String> permissions, String message)
    {
        super(permissions, message);
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     */
    public UserMissingPermissionException(Comparable userId, Collection<String> permissions)
    {
        super(permissions, getDefaultMessage(userId, permissions));
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     * @param message The exception message.
     */
    public UserMissingPermissionException(Comparable userId, Collection<String> permissions, String message)
    {
        super(permissions, message);
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public UserMissingPermissionException(Comparable userId, Iterable<String> permissions, boolean isForAnyPermissions)
    {
        super(permissions, getDefaultMessage(userId, permissions), isForAnyPermissions);
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     * @param message The exception message.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public UserMissingPermissionException(Comparable userId,
                                          Iterable<String> permissions,
                                          String message,
                                          boolean isForAnyPermissions)
    {
        super(permissions, message, isForAnyPermissions);
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public UserMissingPermissionException(Comparable userId,
                                          Collection<String> permissions,
                                          boolean isForAnyPermissions)
    {
        super(permissions, getDefaultMessage(userId, permissions), isForAnyPermissions);
        userMissingPermissionId = userId;
    }

    /**
     * Creates a new UserMissingPermissionException
     * @param userId The ID of the user missing the permissions.
     * @param permissions The permissions missing.
     * @param message The exception message.
     * @param isForAnyPermissions Whether allowing *any* of the permissions would be permissible.
     */
    public UserMissingPermissionException(Comparable userId,
                                          Collection<String> permissions,
                                          String message,
                                          boolean isForAnyPermissions)
    {
        super(permissions, message, isForAnyPermissions);
        userMissingPermissionId = userId;
    }
    //endregion

    //region Static util methods for initialisation
    /**
     * Gets the default exception message for a given iterable of permissions.
     * @param permissions The permissions to get the default exception message for.
     * @return The default exception message.
     */
    private static String getDefaultMessage(Comparable userId, Iterable<String> permissions)
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
            result = "The user with the ID " + userId.toString() + "was missing the permission "
                     + resultBuilder.substring(linePrefix.length() + 1);
        }
        else
        { result = "The user with the ID " + userId.toString() + "was missing the permissions: " + resultBuilder; }

        return result;
    }

    /**
     * Gets the default exception message for a given collection of permissions.
     * @param permissions The permissions to get the default exception message for.
     * @return The default exception message.
     */
    private static String getDefaultMessage(Comparable userId, Collection<String> permissions)
    {
        if(permissions.size() != 1)
        {
            //noinspection OptionalGetWithoutIsPresent
            return "The user with the ID " + userId + " was missing the permission "
                   + permissions.stream().findFirst().get();
        }

        StringBuilder resultBuilder = new StringBuilder();
        String linePrefix = "  - ";

        for(String p : permissions)
            resultBuilder.append("\n").append(linePrefix).append(p);

        return "The user with the ID " + userId + " was missing the permissions: " + resultBuilder;
    }
    //endregion
    //endregion

    //region Methods
    /**
     * Gets the ID of the user missing the permission.
     * @return The ID of the user missing the permission.
     */
    public Comparable getUserId()
    { return userMissingPermissionId; }
    //endregion
}
