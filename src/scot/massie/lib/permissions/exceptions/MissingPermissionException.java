package scot.massie.lib.permissions.exceptions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Thrown when asserting that something has a permission which it does not.
 */
public class MissingPermissionException extends Exception
{
    /**
     * The permissions missing.
     */
    final List<String> permissionsMissing;

    /**
     * Creates a new MissingPermissionException.
     * @param permission The permission missing.
     */
    public MissingPermissionException(String permission)
    { this(permission, getDefaultMessage(Collections.singletonList(permission))); }

    /**
     * Creates a new MissingPermissionException.
     * @param permission The permission missing.
     * @param message The exception message.
     */
    public MissingPermissionException(String permission, String message)
    {
        super(message);
        this.permissionsMissing = Collections.singletonList(permission);
    }

    /**
     * Creates a new MissingPermissionException.
     * @param permissions The permissions missing.
     */
    public MissingPermissionException(Iterable<String> permissions)
    { this(permissions, getDefaultMessage(permissions)); }

    /**
     * Creates a new MissingPermissionException.
     * @param permissions The permissions missing.
     * @param message The exception message.
     */
    public MissingPermissionException(Iterable<String> permissions, String message)
    {
        super(message);
        List<String> psMissing = new ArrayList<>();

        for(String p : permissions)
            psMissing.add(p);

        this.permissionsMissing = Collections.unmodifiableList(psMissing);
    }

    /**
     * Creates a new MissingPermissionException.
     * @param permissions The permissions missing.
     */
    public MissingPermissionException(Collection<String> permissions)
    { this(permissions, getDefaultMessage(permissions)); }

    /**
     * Creates a new MissingPermissionException.
     * @param permissions The permissions missing.
     * @param message The exception message.
     */
    public MissingPermissionException(Collection<String> permissions, String message)
    {
        super(message);
        this.permissionsMissing = Collections.unmodifiableList(new ArrayList<>(permissions));
    }

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
        { result = "Missing the permission " + resultBuilder.substring(linePrefix.length() + 1); }
        else
        { result = "Missing the permissions: " + resultBuilder.toString(); }

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
            //noinspection OptionalGetWithoutIsPresent
            return "Missing the permission " + permissions.stream().findFirst().get();

        StringBuilder resultBuilder = new StringBuilder();
        String linePrefix = "  - ";

        for(String p : permissions)
            resultBuilder.append("\n").append(linePrefix).append(p);

        return "Missing the permissions: " + resultBuilder;
    }

    /**
     * Gets the single permission that was missing.
     * @return The permission that was missing. If multiple permissions were missing, returns one of them.
     */
    public String getPermission()
    { return permissionsMissing.get(0); }

    /**
     * Gets all permissions that were missing.
     * @return A collection of the permissions that were missing.
     */
    public Collection<String> getPermissions()
    { return permissionsMissing; }

    /**
     * Gets whether multiple permissions were missing.
     * @return True if more than one permission was missing. Otherwise, false.
     */
    public boolean multiplePermissionsWereMissing()
    { return permissionsMissing.size() > 1; }
}
