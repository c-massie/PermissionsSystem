package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * <p>A registry for assigning permissions to users in a system and checking them.</p>
 *
 * <p>Users may be assigned permissions to indicate allowance to do something, or to provide some level of per-user
 * configurability.</p>
 *
 * <p>Permissions are provided as dot-separated alphanumeric strings. (e.g. "first.second.third") A permission is said
 * to "cover" another permission where the other permission starts with the dot-separated sections ("nodes") of the
 * first, in order. (e.g. "first.second.third" covers "first.second.third.fourth", but not "first.second.fourth" or
 * "second.first.third.fourth") A permission does not cover another where the other starts with the first, but doesn't
 * have the first's last node exactly. (e.g. "first.second.thi" does not cover "first.second.third" or
 * "first.second.third.fourth")</p>
 *
 * <p>The "most relevant permission" a user has to a given permission is the permission the user has that covers the
 * given permission with the most number of nodes.</p>
 *
 * <p>Users may be assigned "Groups", which are referred to by name, as strings. Groups may have their own permissions
 * and may be assigned other groups. Groups may also have "priorities" (numbers) associated with them. Where a user or
 * group does not have a given permission, it then checks the groups it is assigned, in order of priority from highest
 * to lowest, to see if they cover the given permission.</p>
 *
 * <p>A default "*" group may be defined with permissions and/or groups, which all users are considered to have assigned
 * to them. This may be thought of as a lowest priority group associated with all users.</p>
 *
 * <p>Permissions may be prefixed with a "-" to indicate that a user does *not* have the given permission, that that
 * permission is negated. If the most relevant permission to a given permission a user or group has is negating, that
 * user or group is considered not to have the given permission.</p>
 *
 * <p>Permissions may be suffixed with a ".*" to indicate that they cover permissions longer than it, but not the
 * permission itself. ("first.second.*" covers "first.second.third", but not "first.second")</p>
 *
 * <p>Permissions may be followed by (after any suffixes) a colon (":") and any arbitrary string. This string is the
 * "permission argument". When getting the permission argument of a given permission, it returns the argument of the
 * most relevant permission. Permission arguments may be multiple lines.</p>
 * @param <ID> The type of the unique identifier used to represent users.
 */
public class PermissionsRegistry<ID extends Comparable<? super ID>>
{
    //region Inner classes
    //region Exceptions
    /**
     * Base exception for PermissionsRegistry-related exceptions.
     */
    public static class PermissionsRegistryException extends RuntimeException
    {
        public PermissionsRegistryException() { super(); }
        public PermissionsRegistryException(String message) { super(message); }
        public PermissionsRegistryException(Throwable cause) { super(cause); }
        public PermissionsRegistryException(String message, Throwable cause) { super(message, cause); }
    }

    /**
     * Exception for attempting to create a group with an invalid name.
     */
    public static class InvalidGroupNameException extends PermissionsRegistryException
    {
        public InvalidGroupNameException(String groupNameString)
        {
            super();
            this.groupNameString = groupNameString;
        }

        public InvalidGroupNameException(String groupNameString, String message)
        {
            super(message);
            this.groupNameString = groupNameString;
        }

        public InvalidGroupNameException(String groupNameString, Throwable cause)
        {
            super(cause);
            this.groupNameString = groupNameString;
        }

        public InvalidGroupNameException(String groupNameString, String message, Throwable cause)
        {
            super(message, cause);
            this.groupNameString = groupNameString;
        }

        protected final String groupNameString;

        /**
         * Gets the invalid group name string that caused this exception.
         * @return The invalid group name string that caused this exception.
         */
        public String getGroupNameString()
        { return groupNameString; }
    }

    /**
     * Exception for attempting to parse a permission string that is not parsable as a permission.
     */
    public static class InvalidPermissionException extends PermissionsRegistryException
    {
        public InvalidPermissionException(String permission)
        {
            super();
            this.permissionString = permission;
        }

        public InvalidPermissionException(String permission, String message)
        {
            super(message);
            this.permissionString = permission;
        }

        public InvalidPermissionException(String permission, Throwable cause)
        {
            super(cause);
            this.permissionString = permission;
        }

        public InvalidPermissionException(String permission, String message, Throwable cause)
        {
            super(message, cause);
            this.permissionString = permission;
        }

        protected final String permissionString;

        /**
         * Gets the unparsable permission string that caused this exception.
         * @return The unparsable permission string that caused this exception.
         */
        public String getPermissionString()
        { return permissionString; }
    }

    /**
     * Exception for attempting to parse a string as a group priority that cannot be read as a number.
     */
    public static class InvalidPriorityException extends NumberFormatException
    {
        public InvalidPriorityException(String invalidPriority)
        {
            super("Invalid permission group priority: " + invalidPriority);
            this.invalidPriority = invalidPriority;
        }

        protected final String invalidPriority;

        /**
         * Gets the string that cannot be read as a number, which caused this exception.
         * @return The string that cannot be read as a number, which caused this exception.
         */
        public String getInvalidPriority()
        { return invalidPriority; }
    }

    /**
     * Exception for attempting to assign a group to another group when the assignment would cause both groups to
     * extend from each-other.
     */
    public static class CircularGroupHierarchyException extends PermissionsRegistryException
    {
        public CircularGroupHierarchyException(String ancestorGroupName,
                                               String descendantGroupName)
        {
            super();
            this.currentAncestorGroupName = ancestorGroupName;
            this.currentDescendantGroupName = descendantGroupName;
        }

        public CircularGroupHierarchyException(String ancestorGroupName,
                                               String descendantGroupName,
                                               String msg)
        {
            super(msg);
            this.currentAncestorGroupName = ancestorGroupName;
            this.currentDescendantGroupName = descendantGroupName;
        }

        public CircularGroupHierarchyException(String ancestorGroupName,
                                               String descendantGroupName,
                                               Throwable cause)
        {
            super(cause);
            this.currentAncestorGroupName = ancestorGroupName;
            this.currentDescendantGroupName = descendantGroupName;
        }

        public CircularGroupHierarchyException(String ancestorGroupName,
                                               String descendantGroupName,
                                               String message,
                                               Throwable cause)
        {
            super(message, cause);
            this.currentAncestorGroupName = ancestorGroupName;
            this.currentDescendantGroupName = descendantGroupName;
        }

        protected final String currentAncestorGroupName;
        protected final String currentDescendantGroupName;

        /**
         * Gets the name of the group that, before the exception was thrown, was extended by the other.
         * @return The name of the ancestor group.
         */
        public String getCurrentAncestorGroupName()
        { return currentAncestorGroupName; }

        /**
         * Gets the name of the group that, before the exception was thrown, descended from the other.
         * @return The name of the descendant group.
         */
        public String getCurrentDescendantGroupName()
        { return currentDescendantGroupName; }
    }
    //endregion

    //region Text parsing
    /**
     * <p>Reader for parsing text in the registry's save string format.</p>
     *
     * <p>Primarily exists to merge multiple lines that make up on logical line in a save string into single lines
     * possibly containing newline characters.</p>
     *
     * <p>A line in this sense may make up multiple actual lines where a permission is spread across multiple lines -
     * e.g. where a permission has a multi-line permission argument.</p>
     */
    private static class PermissionsLineReader extends Reader
    {
        /**
         * Creates a new PermissionLineReader which reads from the provided reader object.
         * @param source The reader to read text from.
         */
        public PermissionsLineReader(Reader source)
        { this.source = source; }

        private final Reader source;
        private String heldOverLine = null;
        private boolean lastLineReadDumblyHadStringArg = false;

        /**
         * <p>Reads lines from the contained reader without considering logical lines that may span across multiple
         * actual lines.</p>
         *
         * <p>Has the side effect of setting {@link #lastLineReadDumblyHadStringArg} when reading a line containing a
         * permission argument, so that it can be determined by {@link #readLine()} whether the multiple actual lines
         * are part of the same logical line.</p>
         * @return The next line, or null if there are no more lines.
         * @throws IOException If an IO exception is thrown by the contained reader in the process of reading from it.
         */
        private String readLineDumbly() throws IOException
        {
            StringBuilder sb = new StringBuilder();
            boolean eligibleForStringArg = false;
            boolean foundNonWhitespaceChars = false;
            boolean hasStringArg = false;

            for(int ci = source.read(); ci != '\n'; ci = source.read())
            {
                if(ci == -1)
                {
                    if(sb.length() == 0)
                        return null;

                    String line = sb.toString();

                    if(line.endsWith("\r"))
                        line = line.substring(0, line.length() - 1);

                    return line;
                }

                char c = (char)ci;
                sb.append(c);

                if(c != ' ')
                    foundNonWhitespaceChars = true;

                if(!foundNonWhitespaceChars)
                    eligibleForStringArg = true;

                if((eligibleForStringArg) && (c == ':'))
                    hasStringArg = true;
            }

            String line = sb.toString();

            if(line.endsWith("\r"))
                line = line.substring(0, line.length() - 1);

            lastLineReadDumblyHadStringArg = hasStringArg;
            return line;
        }

        private static int getIndentLevel(String of)
        {
            // Assumes a single-line line
            int stringLength = of.length();

            for(int i = 0; i < stringLength; i++)
                if(of.charAt(i) != ' ')
                    return i;

            return stringLength;
        }

        /**
         * Gets a single line of the save string this reads from. A single line in this sense may include newline
         * characters where a permission has a multi-line permission argument.
         * @return The next line, or null if there are no more lines to read.
         * @throws IOException If the reader this wraps throws an IO exception in the process of reading from it.
         */
        public String readLine() throws IOException
        {
            String line;

            if(heldOverLine != null)
            {
                line = heldOverLine;
                heldOverLine = null;
            }
            else
            {
                line = readLineDumbly();

                if(line == null)
                    return null;
            }

            if(!lastLineReadDumblyHadStringArg)
                return line;

            int lineIndentLevel = getIndentLevel(line);
            String nextLine;
            StringBuilder lineBuilder = new StringBuilder(line);

            while(((nextLine = readLineDumbly()) != null) && ((lineIndentLevel + 4) <= getIndentLevel(nextLine)))
                lineBuilder.append("\n").append(nextLine.substring(lineIndentLevel));

            heldOverLine = nextLine;
            return lineBuilder.toString();
        }

        @Override
        public int read(char[] cbuf, int off, int len) throws IOException
        { return source.read(cbuf, off, len); }

        @Override
        public void close() throws IOException
        { source.close(); }
    }
    //endregion
    //endregion

    //region Instance fields
    /**
     * The permission groups for users, mapped against the IDs of the users they're permissions for.
     */
    protected final Map<ID, PermissionGroup> permissionsForUsers = new HashMap<>();

    /**
     * The permission groups for groups, mapped against the names of the groups.
     */
    protected final Map<String, PermissionGroup> assignableGroups = new HashMap<>();

    /**
     * The default permission group.
     */
    protected final PermissionGroup defaultPermissions;


    /**
     * Converter for converting user IDs into a string form.
     */
    protected final Function<ID, String> convertIdToString;

    /**
     * Converter for converting user IDs from their string form back into user IDs.
     */
    protected final Function<String, ID> parseIdFromString;


    /**
     * The filepath of the users permissions save file.
     */
    protected final Path usersFilePath;

    /**
     * The filepath of the groups permissions save file.
     */
    protected final Path groupsFilePath;


    /**
     * Flag indicating whether or not the permissions registry has been modified since it was last saved or loaded.
     */
    protected boolean hasBeenDifferentiatedFromFiles = false;
    //endregion

    //region Initialisation
    protected PermissionsRegistry(PermissionGroup defaultPermissions,
                                  Function<ID, String> idToString,
                                  Function<String, ID> idFromString,
                                  Path usersFile,
                                  Path groupsFile)
    {
        this.defaultPermissions = defaultPermissions;
        this.convertIdToString = idToString;
        this.parseIdFromString = idFromString;
        this.usersFilePath = usersFile;
        this.groupsFilePath = groupsFile;
    }

    /**
     * Creates a new permissions registry with the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public PermissionsRegistry(Function<ID, String> idToString,
                               Function<String, ID> idFromString,
                               Path usersFile,
                               Path groupsFile)
    { this(new PermissionGroup("*"), idToString, idFromString, usersFile, groupsFile); }

    protected PermissionsRegistry(PermissionGroup defaultPermissions,
                                  Function<ID, String> idToString,
                                  Function<String, ID> idFromString)
    { this(defaultPermissions, idToString, idFromString, null, null); }

    /**
     * Creates a new permissions registry without the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public PermissionsRegistry(Function<ID, String> idToString,
                               Function<String, ID> idFromString)
    { this(new PermissionGroup("*"), idToString, idFromString, null, null); }
    //endregion

    //region Methods
    //region Static utils
    /**
     * Asserts that a string is a valid name for a group.
     * @param groupName The string to assert is a valid group name.
     * @throws InvalidGroupNameException If the given group name is not a valid name.
     */
    protected static void assertGroupNameValid(String groupName)
    {
        groupName.codePoints().forEach(codePoint ->
        {
            if(!Character.isLetterOrDigit(codePoint))
                throw new InvalidGroupNameException(groupName);
        });
    }

    /**
     * Assets that assigning a group another group wouldn't result in a circular hierarchy.
     * @param subgroup The proposed subgroup.
     * @param supergroup The proposed supergroup.
     */
    protected static void assertNotCircular(PermissionGroup subgroup, PermissionGroup supergroup)
    {
        if((subgroup == supergroup) || (supergroup.hasGroup(supergroup.getName())))
            throw new CircularGroupHierarchyException(subgroup.getName(), supergroup.getName());
    }
    //endregion

    //region Assertions
    //region Permissions
    //region Has
    /**
     * Asserts that a specified user "has" a given permission.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to assert has the given permission.
     * @param permission The permission to assert that the user has.
     * @throws UserMissingPermissionException If the user does not have the given permission.
     */
    public void assertUserHasPermission(ID userId, String permission) throws UserMissingPermissionException
    {
        if(!userHasPermission(userId, permission))
            throw new UserMissingPermissionException(userId, permission);
    }

    /**
     * Asserts that a specified group "has" a given permission.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to assert has the given permission
     * @param permission The permission to assert that the group has.
     * @throws GroupMissingPermissionException If the group does not have the given permission.
     */
    public void assertGroupHasPermission(String groupName, String permission) throws GroupMissingPermissionException
    {
        if(!groupHasPermission(groupName, permission))
            throw new GroupMissingPermissionException(groupName, permission);
    }

    /**
     * Asserts that a given permission is part of the default permissions.
     * @param permission The permission to assert is default.
     * @throws PermissionNotDefaultException If the default permissions does not include the given permission.
     */
    public void assertIsDefaultPermission(String permission) throws PermissionNotDefaultException
    {
        if(!isDefaultPermission(permission))
            throw new PermissionNotDefaultException(permission);
    }
    //endregion

    //region Has all
    /**
     * Asserts that the specified user "has" all of the given permissions.
     * @see #userHasAllPermissions(Comparable, Iterable)
     * @param userId The ID of the user to assert has all of the given permissions
     * @param permissions The permissions to assert that the user has.
     * @throws UserMissingPermissionException If the user is missing any of the given permissions.
     */
    public void assertUserHasAllPermissions(ID userId, Iterable<String> permissions)
            throws UserMissingPermissionException
    {
        if(!userHasAllPermissions(userId, permissions))
        {
            List<String> permissionsMissing = new ArrayList<>();

            for(String perm : permissions)
                if(!userHasPermission(userId, perm))
                    permissionsMissing.add(perm);

            throw new UserMissingPermissionException(userId, permissionsMissing);
        }
    }

    /**
     * Asserts that the specified user "has" all of the given permissions.
     * @see #userHasAllPermissions(Comparable, String...)
     * @param userId The ID of the user to assert has all of the given permissions
     * @param permissions The permissions to assert that the user has.
     * @throws UserMissingPermissionException If the user is missing any of the given permissions.
     */
    public void assertUserHasAllPermissions(ID userId, String... permissions)
            throws UserMissingPermissionException
    { assertUserHasAllPermissions(userId, Arrays.asList(permissions)); }

    /**
     * Asserts that the specified group "has" all of the given permissions.
     * @see #groupHasAllPermissions(String, Iterable)
     * @param groupName The name of the group to assert has all of the given permissions
     * @param permissions The permissions to assert that the group has.
     * @throws GroupMissingPermissionException If the group is missing any of the given permissions.
     */
    public void assertGroupHasAllPermissions(String groupName, Iterable<String> permissions)
            throws GroupMissingPermissionException
    {
        if(!groupHasAllPermissions(groupName, permissions))
        {
            List<String> permissionsMissing = new ArrayList<>();

            for(String perm : permissions)
                if(!groupHasPermission(groupName, perm))
                    permissionsMissing.add(perm);

            throw new GroupMissingPermissionException(groupName, permissionsMissing);
        }
    }

    /**
     * Asserts that the specified group "has" all of the given permissions.
     * @see #groupHasAllPermissions(String, String...)
     * @param groupName The name of the group to assert has all of the given permissions
     * @param permissions The permissions to assert that the group has.
     * @throws GroupMissingPermissionException If the group is missing any of the given permissions.
     */
    public void assertGroupHasAllPermissions(String groupName, String... permissions)
            throws GroupMissingPermissionException
    { assertGroupHasAllPermissions(groupName, Arrays.asList(permissions)); }

    /**
     * Asserts that all of the given permissions are default.
     * @see #areAllDefaultPermissions(Iterable)
     * @param permissions The permissions to assert are all default.
     * @throws PermissionNotDefaultException If the default permissions does not cover any of the given permissions.
     */
    public void assertAllAreDefaultPermissions(Iterable<String> permissions)
            throws PermissionNotDefaultException
    {
        if(!areAllDefaultPermissions(permissions))
        {
            List<String> permissionsMissing = new ArrayList<>();

            for(String perm : permissions)
                if(!isDefaultPermission(perm))
                    permissionsMissing.add(perm);

            throw new PermissionNotDefaultException(permissionsMissing);
        }
    }

    /**
     * Asserts that all of the given permissions are default.
     * @see #areAllDefaultPermissions(String...)
     * @param permissions The permissions to assert are all default.
     * @throws PermissionNotDefaultException If the default permissions does not cover any of the given permissions.
     */
    public void assertAllAreDefaultPermissions(String... permissions)
            throws PermissionNotDefaultException
    { assertAllAreDefaultPermissions(Arrays.asList(permissions)); }
    //endregion

    //region Has any
    /**
     * Asserts that the specified user "has" any of the given permissions.
     * @see #userHasAnyPermissions(Comparable, Iterable)
     * @param userId The ID of the user to assert has any of the given permissions
     * @param permissions The permissions to assert that the user has any of.
     * @throws UserMissingPermissionException If the user has none of the given permissions.
     */
    public void assertUserHasAnyPermission(ID userId, Iterable<String> permissions)
            throws UserMissingPermissionException
    {
        if(!userHasAnyPermissions(userId, permissions))
            throw new UserMissingPermissionException(userId, permissions, true);
    }

    /**
     * Asserts that the specified user "has" any of the given permissions.
     * @see #userHasAnyPermissions(Comparable, String...)
     * @param userId The ID of the user to assert has any of the given permissions
     * @param permissions The permissions to assert that the user has any of.
     * @throws UserMissingPermissionException If the user has none of the given permissions.
     */
    public void assertUserHasAnyPermission(ID userId, String... permissions)
            throws UserMissingPermissionException
    { assertUserHasAnyPermission(userId, Arrays.asList(permissions)); }

    /**
     * Asserts that the specified group "has" any of the given permissions.
     * @see #groupHasAnyPermissions(String, Iterable)
     * @param groupName The name of the group to assert has any of the given permissions
     * @param permissions The permissions to assert that the group has any of.
     * @throws GroupMissingPermissionException If the group has none of the given permissions.
     */
    public void assertGroupHasAnyPermission(String groupName, Iterable<String> permissions)
            throws GroupMissingPermissionException
    {
        if(!groupHasAnyPermissions(groupName, permissions))
            throw new GroupMissingPermissionException(groupName, permissions, true);
    }

    /**
     * Asserts that the specified group "has" any of the given permissions.
     * @see #groupHasAnyPermissions(String, String...)
     * @param groupName The name of the group to assert has any of the given permissions
     * @param permissions The permissions to assert that the group has any of.
     * @throws GroupMissingPermissionException If the group has none of the given permissions.
     */
    public void assertGroupHasAnyPermission(String groupName, String... permissions)
            throws GroupMissingPermissionException
    { assertGroupHasAnyPermission(groupName, Arrays.asList(permissions)); }

    /**
     * Asserts that any of the given permissions are default.
     * @see #anyAreDefaultPermissions(Iterable)
     * @param permissions The permissions to assert are default.
     * @throws PermissionNotDefaultException If none of the given permissions are default.
     */
    public void assertAnyAreDefaultPermission(Iterable<String> permissions)
            throws PermissionNotDefaultException
    {
        if(!anyAreDefaultPermissions(permissions))
            throw new PermissionNotDefaultException(permissions, true);
    }

    /**
     * Asserts that any of the given permissions are default.
     * @see #anyAreDefaultPermissions(String...)
     * @param permissions The permissions to assert are default.
     * @throws PermissionNotDefaultException If none of the given permissions are default.
     */
    public void assertAnyAreDefaultPermission(String... permissions)
            throws PermissionNotDefaultException
    { assertAnyAreDefaultPermission(Arrays.asList(permissions)); }
    //endregion
    //endregion
    //endregion

    //region Accessors
    //region Permission queries
    //region Get status
    //region Single
    /**
     * Gets all the status information pertaining to the direct relationship between the specified user and the given
     * permission.
     * @param userId The ID of the user to get the status information of the given permission.
     * @param permission The permission to get the status of relating to the specified user.
     * @return A PermissionStatus object containing the permission queried, whether or not the user "has" it, and the
     *         permission argument if applicable.
     */
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { return getPermissionStatus(permissionsForUsers.get(userId), permission, true); }

    /**
     * Gets all the status information pertaining to the direct relationship between the specified group and the given
     * permission.
     * @param groupName The name of the group to get the status information of the given permission.
     * @param permission The permission to get the status of relating to the specified group.
     * @return A PermissionStatus object containing the permission queried, whether or not the group "has" it, and the
     *         permission argument if applicable.
     */
    public PermissionStatus getGroupPermissionStatus(String groupName, String permission)
    { return getPermissionStatus(getGroupPermissionsGroup(groupName), permission, false); }

    /**
     * Gets all the status information pertaining to the direct relationship between the default permissions and the
     * given permission.
     * @param permission The permission to get the status of relating to the default permissions.
     * @return A permissionStatus object containing the permission queried, whether or not the permission is included
     *         in the default permissions, and the permission argument if applicable.
     */
    public PermissionStatus getDefaultPermissionStatus(String permission)
    { return getPermissionStatus(defaultPermissions, permission, false); }

    /**
     * Gets all the status information pertaining to the direct relationship between the given permission group object
     * and the given permission.
     * @param permGroup The permission group object to get the status information of the given permission.
     * @param permission The permission to get the status information of relating to the given permission group object.
     * @param deferToDefault Whether or not to defer to the default permission group object where the given permission
     *                       group object is null.
     * @return A PermissionStatus object containing the permission queried, whether or not the permission group "has"
     *         it, and the permission argument if applicable.
     */
    protected PermissionStatus getPermissionStatus(PermissionGroup permGroup, String permission, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault ? defaultPermissions.getPermissionStatus(permission)
                                  : new PermissionStatus(permission, false, null);

        return permGroup.getPermissionStatus(permission);
    }
    //endregion

    //region Multiple
    /**
     * Gets all the status information pertaining to the direct relationship between the specified user and each of the
     * given permissions.
     * @param userId The ID of the user to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified user.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the user "has" it, and the permission argument if applicable.
     */
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, Iterable<String> permissions)
    { return getPermissionStatuses(permissionsForUsers.get(userId), permissions, true); }

    /**
     * Gets all the status information pertaining to the direct relationship between the specified user and each of the
     * given permissions.
     * @param userId The ID of the user to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified user.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the user "has" it, and the permission argument if applicable.
     */
    public Map<String, PermissionStatus> getUserPermissionStatuses(ID userId, String... permissions)
    { return getPermissionStatuses(permissionsForUsers.get(userId), Arrays.asList(permissions), true); }

    /**
     * Gets all the status information pertaining to the direct relationship between the specified group and each of the
     * given permissions.
     * @param groupName The name of the group to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified group.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the group "has" it, and the permission argument if applicable.
     */
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, Iterable<String> permissions)
    { return getPermissionStatuses(getGroupPermissionsGroup(groupName), permissions, false); }

    /**
     * Gets all the status information pertaining to the direct relationship between the specified group and each of the
     * given permissions.
     * @param groupName The name of the group to get the status information of the given permissions.
     * @param permissions The permissions to get the status of relating to the specified group.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the group "has" it, and the permission argument if applicable.
     */
    public Map<String, PermissionStatus> getGroupPermissionStatuses(String groupName, String... permissions)
    { return getPermissionStatuses(getGroupPermissionsGroup(groupName), Arrays.asList(permissions), false); }

    /**
     * Gets all the status information pertaining to the direct relationship between the default permissions and each of
     * the given permissions.
     * @param permissions The permissions to get the status of relating to the default permissions.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the default permissions "has" it, and the permission argument if
     *         applicable.
     */
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(Iterable<String> permissions)
    { return getPermissionStatuses(defaultPermissions, permissions, false); }

    /**
     * Gets all the status information pertaining to the direct relationship between the default permissions and each of
     * the given permissions.
     * @param permissions The permissions to get the status of relating to the default permissions.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the default permissions "has" it, and the permission argument if
     *         applicable.
     */
    public Map<String, PermissionStatus> getDefaultPermissionStatuses(String... permissions)
    { return getPermissionStatuses(defaultPermissions, Arrays.asList(permissions), false); }

    /**
     * Gets all the status information pertaining to the direct relationship between the given permission group object
     * and the given permissions.
     * @param permGroup The permission group object to get the status information of the given permissions.
     * @param permissions The permissions to get the status information of relating to the given permission group
     *                    object.
     * @param deferToDefault Whether or not to defer to the default permission group object where the given permission
     *                       group object is null.
     * @return A map where the keys are the permissions specified and the values are PermissionStatus objects containing
     *         the permission queried, whether or not the given permission group object "has" it, and the permission
     *         argument if applicable.
     */
    protected Map<String, PermissionStatus> getPermissionStatuses(PermissionGroup permGroup,
                                                                  Iterable<String> permissions,
                                                                  boolean deferToDefault)
    {
        Map<String, PermissionStatus> result = new HashMap<>();

        if(permGroup == null)
        {
            if(deferToDefault)
            {
                for(String permission : permissions)
                    result.put(permission, defaultPermissions.getPermissionStatus(permission));
            }
            else
            {
                for(String permission : permissions)
                    result.put(permission, new PermissionStatus(permission, false, null));
            }

            return result;
        }

        for(String permission : permissions)
            result.put(permission, permGroup.getPermissionStatus(permission));

        return result;
    }
    //endregion
    //endregion

    //region Has
    /**
     * <p>Checks whether or not a specified user "has" a given permission.</p>
     *
     * <p>That is, checks whether the given user's permissions contains (directly, via a group it's assigned, or via the
     * default permissions) at least one permission that covers the given permission, and whether the most relevant
     * permission of the given user to the given permission is an allowing permission. (as opposed to a negating
     * permission.)</p>
     * @param userId The ID of the user to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the user has the given permission as defined above. Otherwise, false.
     */
    public boolean userHasPermission(ID userId, String permission)
    { return hasPermission(permissionsForUsers.get(userId), permission, true); }

    /**
     * <p>Checks whether or not a specified group "has" a given permission.</p>
     *
     * <p>That is, checks whether the given group's permissions contains (directly or via a group it extends from, but
     * not via the default permissions) at least one permission that covers the given permission, and whether the most
     * relevant permission of the given group to the given permission is an allowing permission. (as opposed to a
     * negating permission.)</p>
     * @param groupName The name of the group to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the group has the given permission as defined above. Otherwise, false.
     */
    public boolean groupHasPermission(String groupName, String permission)
    { return hasPermission(getGroupPermissionsGroup(groupName), permission, false); }

    /**
     * <p>Checks whether or not the default permissions "has" a given permission.</p>
     *
     * <p>That is, checks whether the default permissions contains (directly or via a group assigned as a default group)
     * at least one permission that covers the given permission, and whether the most relevant permission of the default
     * permissions is an allowing permission. (as opposed to a negating permission.)</p>
     * @param permission The permission to check for.
     * @return True if the default permissions has the given permission as defined above. Otherwise, false.
     */
    public boolean isDefaultPermission(String permission)
    { return hasPermission(defaultPermissions, permission, false); }

    /**
     * <p>Checks whether or not a given permission group object "has" a given permission.</p>
     *
     * <p>That is, checks whether the given permission group object contains (directly or via another referenced
     * permission group object) a permission that covers the given permission, and if so, whether the most relevant
     * permission to the given one is allowing.</p>
     * @param permGroup The permission group object to check for the allowance of the given permission.
     * @param permission The permission to check for.
     * @param deferToDefault Whether or not to defer to the default permission group object where the given permission
     *                       group object is null.
     * @return <p>True if any of the following are true:</p>
     *
     *         <ul>
     *             <il>
     *                 <p>All of the following are true:</p>
     *                 <ul>
     *                     <il><p>The given permission group object is non-null.</p></il>
     *                     <il>
     *                         <p>It, or any other permission group objects it references, (which may or may not include
     *                         the default permission group object) contains a permission that covers the given
     *                         permission.</p>
     *                     </il>
     *                     <il>
     *                         <p>The most relevant permission within the given permission group is an allowing one.</p>
     *                     </il>
     *                 </ul>
     *             </il>
     *             <il>
     *                 <p>The given permission group object is null, deferToDefault is true, and the default
     *                 PermissionGroup object "has" the given permission.</p>
 *                 </il>
     *         </ul>
     */
    protected boolean hasPermission(PermissionGroup permGroup, String permission, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault && defaultPermissions.hasPermission(permission);

        return permGroup.hasPermission(permission);
    }
    //endregion

    //region Has all

    /**
     * Checks whether or not a specified user has all of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has all of the given permissions. Otherwise, false.
     */
    public boolean userHasAllPermissions(ID userId, Iterable<String> permissions)
    { return hasAllPermissions(permissionsForUsers.get(userId), permissions, true); }

    /**
     * Checks whether or not a specified user has all of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has all of the given permissions. Otherwise, false.
     */
    public boolean userHasAllPermissions(ID userId, String... permissions)
    { return hasAllPermissions(permissionsForUsers.get(userId), Arrays.asList(permissions), true); }

    /**
     * Checks whether or not a specified group has all of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has all of the given permissions. Otherwise, false.
     */
    public boolean groupHasAllPermissions(String groupName, Iterable<String> permissions)
    { return hasAllPermissions(getGroupPermissionsGroup(groupName), permissions, false); }

    /**
     * Checks whether or not a specified group has all of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has all of the given permissions. Otherwise, false.
     */
    public boolean groupHasAllPermissions(String groupName, String... permissions)
    { return hasAllPermissions(getGroupPermissionsGroup(groupName), Arrays.asList(permissions), false); }

    /**
     * Checks whether or not all given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if all of the given permissions are default. Otherwise, false.
     */
    public boolean areAllDefaultPermissions(Iterable<String> permissions)
    { return hasAllPermissions(defaultPermissions, permissions, false); }

    /**
     * Checks whether or not all given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if all of the given permissions are default. Otherwise, false.
     */
    public boolean areAllDefaultPermissions(String... permissions)
    { return hasAllPermissions(defaultPermissions, Arrays.asList(permissions), false); }

    /**
     * Checks whether or not a given PermissionGroup object has all of the given permissions.
     * @see #hasPermission(PermissionGroup, String, boolean)
     * @param permGroup The permission group object to check for the allowance of the given permissions.
     * @param permissions The permissions to check for.
     * @param deferToDefault Whether or not to defer to the default permission group object where the given permission
     *                       group object is null.
     * @return True if the given PermissionGroup object (or the default PermissionGroup object, if applicable) has all
     *         of the given permissions. Otherwise, false.
     */
    protected boolean hasAllPermissions(PermissionGroup permGroup, Iterable<String> permissions, boolean deferToDefault)
    {
        if(permGroup == null)
        {
            if(deferToDefault)
            {
                for(String permission : permissions)
                    if(!defaultPermissions.hasPermission(permission))
                        return false;
            }
            else
            {
                for(String ignored : permissions) // if permissions.hasAny();
                    return false;
            }

            return true;
        }

        for(String permission : permissions)
            if(!permGroup.hasPermission(permission))
                return false;

        return true;
    }
    //endregion

    //region Has any

    /**
     * Checks whether or not a specified user has any of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions. Otherwise, false.
     */
    public boolean userHasAnyPermissions(ID userId, Iterable<String> permissions)
    { return hasAnyPermissions(permissionsForUsers.get(userId), permissions, true); }

    /**
     * Checks whether or not a specified user has any of the given permissions.
     * @see #userHasPermission(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions. Otherwise, false.
     */
    public boolean userHasAnyPermissions(ID userId, String... permissions)
    { return hasAnyPermissions(permissionsForUsers.get(userId), Arrays.asList(permissions), true); }

    /**
     * Checks whether or not a specified group has any of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions. Otherwise, false.
     */
    public boolean groupHasAnyPermissions(String groupName, Iterable<String> permissions)
    { return hasAnyPermissions(getGroupPermissionsGroup(groupName), permissions, false); }

    /**
     * Checks whether or not a specified group has any of the given permissions.
     * @see #groupHasPermission(String, String)
     * @param groupName The name of the group to check whether or not it has the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions. Otherwise, false.
     */
    public boolean groupHasAnyPermissions(String groupName, String... permissions)
    { return hasAnyPermissions(getGroupPermissionsGroup(groupName), Arrays.asList(permissions), false); }

    /**
     * Checks whether or not any of the given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if any of the given permissions are default. Otherwise, false.
     */
    public boolean anyAreDefaultPermissions(Iterable<String> permissions)
    { return hasAnyPermissions(defaultPermissions, permissions, false); }

    /**
     * Checks whether or not any of the given permissions are default.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if any of the given permissions are default. Otherwise, false.
     */
    public boolean anyAreDefaultPermissions(String... permissions)
    { return hasAnyPermissions(defaultPermissions, Arrays.asList(permissions), false); }

    /**
     * Checks whether or not a given PermissionGroup object has any of the given permissions.
     * @see #hasPermission(PermissionGroup, String, boolean)
     * @param permGroup The permission group object to check for the allowance of the given permissions.
     * @param permissions The permissions to check for.
     * @param deferToDefault Whether or not to defer to the default permission group object where the given permission
     *                       group object is null.
     * @return True if the given PermissionGroup object (or the default PermissionGroup object, if applicable) has any
     *         of the given permissions. Otherwise, false.
     */
    protected boolean hasAnyPermissions(PermissionGroup permGroup, Iterable<String> permissions, boolean deferToDefault)
    {
        if(permGroup == null)
        {
            if(deferToDefault)
            {
                for(String permission : permissions)
                    if(defaultPermissions.hasPermission(permission))
                        return true;
            }
            else
            {
                for(String ignored : permissions) // if permissions.hasAny();
                    return true;
            }

            return false;
        }

        for(String permission : permissions)
            if(permGroup.hasPermission(permission))
                return true;

        return false;
    }
    //endregion

    //region Has any subpermission of

    /**
     * Checks whether or not a specified user "has" a given permission or any subpermission thereof.
     * @see #userHasPermission(Comparable, String)
     * @param userId The user to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the user has the given permission or any subpermission thereof as defined by
     *         {@link #userHasPermission(Comparable, String)}. Otherwise, false.
     */
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { return hasAnySubPermissionOf(permissionsForUsers.get(userId), permission, true); }

    /**
     * Checks whether or not a specified user "has" any of the given permissions or any subpermission thereof.
     * @see #userHasPermission(Comparable, String)
     * @param userId The user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions or any subpermission thereof as defined by
     *         {@link #userHasPermission(Comparable, String)}. Otherwise, false.
     */
    public boolean userHasAnySubPermissionOf(ID userId, Iterable<String> permissions)
    { return hasAnySubPermissionOf(permissionsForUsers.get(userId), permissions, true); }

    /**
     * Checks whether or not a specified user "has" any of the given permissions or any subpermission thereof.
     * @see #userHasPermission(Comparable, String)
     * @param userId The user to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the user has any of the given permissions or any subpermission thereof as defined by
     *         {@link #userHasPermission(Comparable, String)}. Otherwise, false.
     */
    public boolean userHasAnySubPermissionOf(ID userId, String... permissions)
    { return hasAnySubPermissionOf(permissionsForUsers.get(userId), permissions, true); }

    /**
     * Checks whether or not a specified group "has" a given permission or any subpermission thereof.
     * @see #groupHasPermission(String, String)
     * @param groupId The id of the group to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the group has the given permission or any subpermission thereof as defined by
     *         {@link #groupHasPermission(String, String)}. Otherwise, false.
     */
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    { return hasAnySubPermissionOf(getGroupPermissionsGroup(groupId), permission, false); }

    /**
     * Checks whether or not a specified group "has" any of the given permissions or any subpermission thereof.
     * @see #groupHasPermission(String, String)
     * @param groupId The id of the group to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions or any subpermission thereof as defined by
     *         {@link #groupHasPermission(String, String)}. Otherwise, false.
     */
    public boolean groupHasAnySubPermissionOf(String groupId, Iterable<String> permissions)
    { return hasAnySubPermissionOf(getGroupPermissionsGroup(groupId), permissions, false); }

    /**
     * Checks whether or not a specified group "has" any of the given permissions or any subpermission thereof.
     * @see #groupHasPermission(String, String)
     * @param groupId The id of the group to check whether or not they have the given permissions.
     * @param permissions The permissions to check for.
     * @return True if the group has any of the given permissions or any subpermission thereof as defined by
     *         {@link #groupHasPermission(String, String)}. Otherwise, false.
     */
    public boolean groupHasAnySubPermissionOf(String groupId, String... permissions)
    { return hasAnySubPermissionOf(getGroupPermissionsGroup(groupId), permissions, false); }

    /**
     * Checks whether or not the default permissions "has" a given permission or any subpermission thereof.
     * @see #isDefaultPermission(String)
     * @param permission The permission to check for.
     * @return True if the default permissions has the given permission or any subpermission there as defined by
     *         {@link #isDefaultPermission(String)}.
     */
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    { return hasAnySubPermissionOf(defaultPermissions, permission, false); }

    /**
     * Checks whether or not the default permissions "has" any of the given permissions or any subpermission thereof.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if the default permissions has any of the given permissions or any subpermission there as defined by
     *         {@link #isDefaultPermission(String)}.
     */
    public boolean isOrAnySubPermissionOfIsDefault(Iterable<String> permissions)
    { return hasAnySubPermissionOf(defaultPermissions, permissions, false); }

    /**
     * Checks whether or not the default permissions "has" any of the given permissions or any subpermission thereof.
     * @see #isDefaultPermission(String)
     * @param permissions The permissions to check for.
     * @return True if the default permissions has any of the given permissions or any subpermission there as defined by
     *         {@link #isDefaultPermission(String)}.
     */
    public boolean isOrAnySubPermissionOfIsDefault(String... permissions)
    { return hasAnySubPermissionOf(defaultPermissions, permissions, false); }

    /**
     * Checks whether or not a given PermissionGroup object "has" a given permission or any subpermission thereof.
     * @see #hasPermission(PermissionGroup, String, boolean)
     * @param permGroup The permisison group that may have the given permission or any subpermission thereof.
     * @param permission The permissions to check for.
     * @param deferToDefault Whether or not to defer to the default permission group if the given one is null.
     * @return True if the given permission group has the given permission or any subpermission thereof.
     */
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup, String permission, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault && defaultPermissions.hasPermissionOrAnyUnder(permission);

        return permGroup.hasPermissionOrAnyUnder(permission);
    }

    /**
     * Checks whether or not a given PermissionGroup object "has" any of the given permissions or any subpermission
     * thereof.
     * @see #hasPermission(PermissionGroup, String, boolean)
     * @param permGroup The permisison group that may have the given permission or any subpermission thereof.
     * @param permissions The permissions to check for.
     * @param deferToDefault Whether or not to defer to the default permission group if the given one is null.
     * @return True if the given permission group has any of the given permissions or any subpermission thereof.
     */
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup, String[] permissions, boolean deferToDefault)
    { return hasAnySubPermissionOf(permGroup, Arrays.asList(permissions), deferToDefault); }

    /**
     * Checks whether or not a given PermissionGroup object "has" any of the given permissions or any subpermission
     * thereof.
     * @see #hasPermission(PermissionGroup, String, boolean)
     * @param permGroup The permisison group that may have the given permission or any subpermission thereof.
     * @param permissions The permissions to check for.
     * @param deferToDefault Whether or not to defer to the default permission group if the given one is null.
     * @return True if the given permission group has any of the given permissions or any subpermission thereof.
     */
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup,
                                            Iterable<String> permissions,
                                            boolean deferToDefault)
    {
        if(permGroup == null)
        {
            if(deferToDefault)
            {
                for(String perm : permissions)
                    if(defaultPermissions.hasPermissionOrAnyUnder(perm))
                        return true;

            }

            return false;
        }

        for(String perm : permissions)
            if(permGroup.hasPermissionOrAnyUnder(perm))
                return true;

        return false;
    }
    //endregion

    //region Args
    /**
     * <p>Gets the argument associated with the given permission for the given user.</p>
     *
     * <p>That is, where a given user has a permission as described in {@link #userHasPermission(Comparable, String)}
     * and where the most relevant permission a user has to the given permission has a permission argument associated,
     * returns that argument. Otherwise, returns null.</p>
     * @param userId The user to get the permission argument from.
     * @param permission The permission to get the permission argument of.
     * @return If the user has the given permission and the most relevant permission the user has to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    public String getUserPermissionArg(ID userId, String permission)
    { return getPermissionArg(permissionsForUsers.get(userId), permission, true); }

    /**
     * <p>Gets the argument associated with the given permission for the given group.</p>
     *
     * <p>That is, where a given group has a permission as described in {@link #groupHasPermission(String, String)} and
     * where the most relevant permission a group has to the given permission has a permission argument associated,
     * returns that argument. Otherwise, returns null.</p>
     * @param groupId The name of the group to get the permission argument from.
     * @param permission The permission to get the permission argument of.
     * @return If the group has the given permission and the most relevant permission the group has to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    public String getGroupPermissionArg(String groupId, String permission)
    { return getPermissionArg(getGroupPermissionsGroup(groupId), permission, false); }

    /**
     * <p>Gets the argument associated with the given permission in the default permissions.</p>
     *
     * <p>That is, where the default permissions has a permission as described in {@link #isDefaultPermission(String)}
     * and where the most relevant default permission to the given permissions has a permission argument associated,
     * returns that argument. Otherwise, returns null.</p>
     * @param permission The permission to get the permission argument of.
     * @return If the default permissions has the given permission and the most relevant default permission to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    public String getDefaultPermissionArg(String permission)
    { return defaultPermissions.getPermissionArg(permission); }

    /**
     * <p>Gets the permission argument associated with the given permission for the given permission group object, or
     * null if there is none.</p>
     *
     * <p>That is, where a user has a given permission as described in
     * {@link #hasPermission(PermissionGroup, String, boolean)} and where the most relevant permission has a permission
     * argument associated, returns that permission argument. Otherwise, returns null. Returns null if the most relevant
     * permission to the given permission a permission group object has has no permission argument associated with it,
     * even where another permission that covers it does.</p>
     * @param permGroup The permission group object to get a permission argument from.
     * @param permission The permission to get the permission argument of.
     * @param deferToDefault Whether or not to defer to the default permissions where the given permission group object
     *                       is null.
     * @return The string argument associated with the most relevant permission to the given permission in the given
     *         permission group, or null if the given permission group doesn't have that permission, or if the most
     *         relevant permission doesn't have a permission argument associated.
     */
    protected String getPermissionArg(PermissionGroup permGroup, String permission, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault ? defaultPermissions.getPermissionArg(permission) : null;

        return permGroup.getPermissionArg(permission);
    }
    //endregion
    //endregion

    //region Group queries
    //region Has
    /**
     * Gets whether or not the specified user is assigned a group with the given name. (directly, via an assigned group,
     * or via the default permissions.)
     * @param userId The ID of the user to check whether or not they have the specified group.
     * @param groupName The name of the group to check whether or not the user has.
     * @return True if the user, any group assigned to the user, or the default permissions, has a group by the given
     *         name. Otherwise, false.
     */
    public boolean userHasGroup(ID userId, String groupName)
    { return hasGroup(permissionsForUsers.get(userId), groupName, true); }

    /**
     * Gets whether or not one group with the specified name is assigned another, by the other specified name.
     * (directly or via another assigned group, but not via the default permissions.)
     * @param groupId The name of the group to check whether it extends from the other group specified.
     * @param superGroupName The name of the group to check whether the other group specifies it.
     * @return True if the group or any group assigned to the group (that is, that the group is extended from), has a
     *         group assigned to it by the given name. Otherwise, false.
     */
    public boolean groupExtendsFromGroup(String groupId, String superGroupName)
    { return hasGroup(getGroupPermissionsGroup(groupId), superGroupName, false); }

    /**
     * Gets whether or not the group with the specified name is extended from by the default permissions, is assigned
     * as a default group. (directly or via another group assigned as a default group)
     * @param groupId The name of the group to check whether or not is a default group.
     * @return True if the default permissions or any group assigned to the default permissions (assigned as a default
     *         group) is assigned a group by the given name.
     */
    public boolean isDefaultGroup(String groupId)
    { return hasGroup(defaultPermissions, groupId, false); }

    /**
     * Gets whether or not the given permission group object references a permission of the given permission group name,
     * either directly or via another referenced permission group group - or, if allowed, via the default permission
     * group object.
     * @param permGroup The permission group to check whether it references, directly or indirectly, another specified
     *                  permission group.
     * @param groupId The name of group to check for being referenced by the given permission group object.
     * @param deferToDefault Whether or not to check if the default permission group object references the specified
     *                       group where the given permission group object is null.
     * @return <p>True if any of the following are true:</p>
     *
     *         <ul>
     *             <il>
     *                 <p>The given permission group object is non-null and it or any of the groups it references
     *                 directly or indirectly (which may or may not include the default permission group object)
     *                 references the a permission group by the specified name.</p>
     *             </il>
     *             <il>
     *                 <p>The given permission group object is null, deferToDefault is true, and the default permission
     *                 group object, directly or indirectly, extends from a group with the specified name.</p>
     *             </il>
     *         </ul>
     *
     *         <p>Otherwise, false.</p>
     */
    protected boolean hasGroup(PermissionGroup permGroup, String groupId, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault && defaultPermissions.hasGroup(groupId);

        return permGroup.hasGroup(groupId);
    }
    //endregion
    
    //region Has all
    /**
     * Gets whether or not the specified user is assigned groups with all of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by all of the given names. Otherwise, false.
     */
    public boolean userHasAllGroups(ID userId, Iterable<String> groupNames)
    { return hasAllGroups(permissionsForUsers.get(userId), groupNames, true); }

    /**
     * Gets whether or not the specified user is assigned groups with all of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by all of the given names. Otherwise, false.
     */
    public boolean userHasAllGroups(ID userId, String... groupNames)
    { return hasAllGroups(permissionsForUsers.get(userId), Arrays.asList(groupNames), true); }

    /**
     * Gets whether or not the specified group extends from all of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from all of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                      extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by all of the given names. Otherwise, false.
     */
    public boolean groupExtendsFromAllGroups(String groupName, Iterable<String> superGroupNames)
    { return hasAllGroups(getGroupPermissionsGroup(groupName), superGroupNames, false); }

    /**
     * Gets whether or not the specified group extends from all of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from all of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                      extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by all of the given names. Otherwise, false.
     */
    public boolean groupExtendsFromAllGroups(String groupName, String... superGroupNames)
    { return hasAllGroups(getGroupPermissionsGroup(groupName), Arrays.asList(superGroupNames), false); }

    /**
     * Gets whether or not all of the specified groups are default. That is, whether or not they're all included in the
     * default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by all of the given names. Otherwise, false.
     */
    public boolean areAllDefaultGroups(Iterable<String> groupNames)
    { return hasAllGroups(defaultPermissions, groupNames, false); }

    /**
     * Gets whether or not all of the specified groups are default. That is, whether or not they're all included in the
     * default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by all of the given names. Otherwise, false.
     */
    public boolean areAllDefaultGroups(String... groupNames)
    { return hasAllGroups(defaultPermissions, Arrays.asList(groupNames), false); }

    /**
     * Gets whether or not the given permission group object has groups by all of the given names.
     * @see #hasGroup(PermissionGroup, String, boolean)
     * @param permGroup The permission group to check whether or not has all of the given groups.
     * @param groupNames The names of the groups to check whether or not the given permission group object has.
     * @param deferToDefault Whether or not to check if the default permission group object references all of the
     *                       specified groups where the given permission group object is null.
     * @return True if the given permission group object has groups by all of the given names. (directly, or via any of
     *         the other groups it has) Otherwise, false.
     */
    protected boolean hasAllGroups(PermissionGroup permGroup, Iterable<String> groupNames, boolean deferToDefault)
    {
        if(permGroup == null)
        {
            if(deferToDefault)
            {
                for(String groupId : groupNames)
                    if(!defaultPermissions.hasGroup(groupId))
                        return false;
            }
            else
            {
                for(String ignored : groupNames)
                    return false;
            }

            return true;
        }

        for(String groupId : groupNames)
            if(!permGroup.hasGroup(groupId))
                return false;

        return true;
    }
    //endregion
    
    //region Has any
    /**
     * Gets whether or not the specified user is assigned groups with any of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by any of the given names. Otherwise, false.
     */
    public boolean userHasAnyGroups(ID userId, Iterable<String> groupNames)
    { return hasAnyGroups(permissionsForUsers.get(userId), groupNames, true); }

    /**
     * Gets whether or not the specified user is assigned groups with any of the given names. (directly, via an
     * assigned group, or via the default permissions)
     * @see #userHasGroup(Comparable, String)
     * @param userId The ID of the user to check whether or not they have the specified groups.
     * @param groupNames The names of the groups to check whether or not the user has.
     * @return True if the user (directly, or via any of the other groups they have, or via the default permissions) has
     *         groups by any of the given names. Otherwise, false.
     */
    public boolean userHasAnyGroups(ID userId, String... groupNames)
    { return hasAnyGroups(permissionsForUsers.get(userId), Arrays.asList(groupNames), true); }

    /**
     * Gets whether or not the specified group extends from any of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from any of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                        extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by any of the given names. Otherwise, false.
     */
    public boolean groupExtendsFromAnyGroups(String groupName, Iterable<String> superGroupNames)
    { return hasAnyGroups(getGroupPermissionsGroup(groupName), superGroupNames, false); }

    /**
     * Gets whether or not the specified group extends from any of the other specified groups. (directly, via other
     * groups it extends from, or via the default permissions)
     * @see #groupExtendsFromGroup(String, String)
     * @param groupName The name of the group to check whether it extends from any of the other groups.
     * @param superGroupNames The names of all of the other groups to check whether or not the aforementioned group
     *                        extends from.
     * @return True if the group (directly, or via any of the other groups they extend from, or via the default
     *         permissions) extends from groups by any of the given names. Otherwise, false.
     */
    public boolean groupExtendsFromAnyGroups(String groupName, String... superGroupNames)
    { return hasAnyGroups(getGroupPermissionsGroup(groupName), Arrays.asList(superGroupNames), false); }

    /**
     * Gets whether or not any of the specified groups are default. That is, whether or not any of them are included in
     * the default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by any of the given names. Otherwise, false.
     */
    public boolean anyAreDefaultGroups(Iterable<String> groupNames)
    { return hasAnyGroups(defaultPermissions, groupNames, false); }

    /**
     * Gets whether or not any of the specified groups are default. That is, whether or not any of them are included in
     * the default permissions, whether directly or indirectly via other default groups.
     * @see #isDefaultGroup(String)
     * @param groupNames The names of the groups to check whether or not are default.
     * @return True if the default permissions includes (directly, or via any of the other groups they extend from)
     *         groups by any of the given names. Otherwise, false.
     */
    public boolean anyAreDefaultGroups(String... groupNames)
    { return hasAnyGroups(defaultPermissions, Arrays.asList(groupNames), false); }

    /**
     * Gets whether or not the given permission group object has groups by any of the given names.
     * @see #hasGroup(PermissionGroup, String, boolean)
     * @param permGroup The permission group to check whether or not has any of the given groups.
     * @param groupNames The names of the groups to check whether or not the given permission group object has.
     * @param deferToDefault Whether or not to check if the default permission group object references any of the
     *                       specified groups where the given permission group object is null.
     * @return True if the given permission group object has groups by any of the given names. (directly, or via any of
     *         the other groups it has) Otherwise, false.
     */
    protected boolean hasAnyGroups(PermissionGroup permGroup, Iterable<String> groupNames, boolean deferToDefault)
    {
        if(permGroup == null)
        {
            if(deferToDefault)
            {
                for(String groupId : groupNames)
                    if(defaultPermissions.hasGroup(groupId))
                        return true;
            }

            return false;
        }

        for(String groupId : groupNames)
            if(permGroup.hasGroup(groupId))
                return true;

        return false;
    }
    //endregion
    //endregion

    //region State
    /**
     * Gets whether or not the permissions registry has had its values modified since the last time it was saved or
     * loaded.
     * @return True if the permissions registry has been modified since being saved or loaded. Otherwise, false.
     */
    public boolean hasBeenDifferentiatedFromFiles()
    { return hasBeenDifferentiatedFromFiles; }
    //endregion

    //region Getters
    //region Members
    /**
     * Gets the names of all groups registered with the permissions registry. This includes groups that don't have any
     * given permissions and aren't assigned to any users or other groups.
     * @return A collection containing the names of all groups registered with the permissions registry.
     */
    public Collection<String> getGroupNames()
    { return new HashSet<>(assignableGroups.keySet()); }

    /**
     * Gets all users registered with the permissions registry. This includes users that don't have any given
     * permissions.
     * @return A collection containing the IDs of all users registered with the permissions registry.
     */
    public Collection<ID> getUsers()
    { return new HashSet<>(permissionsForUsers.keySet()); }

    /**
     * Gets the path of this registry's users file.
     * @return The path of this registry's users file, or null if this registry has no users file.
     */
    public Path getUsersFilePath()
    { return usersFilePath; }

    /**
     * Gets the path of this registry's groups file.
     * @return The path of this registry's groups file, or null if this registry has no groups file.
     */
    public Path getGroupsFilePath()
    { return groupsFilePath; }

    /**
     * Gets the function responsible for creating string representations of user IDs.
     * @return The function used for converting user IDs into strings.
     */
    public Function<ID, String> getIdToStringFunction()
    { return convertIdToString; }

    /**
     * Gets the function responsible for parsing user IDs from their string representations.
     * @return The function used for converting string representations of user IDs into user IDs.
     */
    public Function<String, ID> getIdFromStringFunction()
    { return parseIdFromString; }
    //endregion

    //region Group priorities
    /**
     * Gets the priority of the group with a given name. (As a double)
     * @param groupName The name of the group to get the priority of.
     * @return The priority of the group by the given name in this permissions registry as a boxed double, or null if
     *         no such group exists.
     */
    public Double getGroupPriority(String groupName)
    {
        PermissionGroup permGroup = getGroupPermissionsGroup(groupName);

        if(permGroup == null)
            return null;

        return permGroup.getPriority();
    }

    /**
     * Gets the priority of the group with a given name. (As a long)
     * @param groupName The name of the group to get the priority of.
     * @return The priority of the group by the given name in this permissions registry as a boxed long, or null if no
     *         such group exists.
     */
    public Long getGroupPriorityAsLong(String groupName)
    {
        PermissionGroup permGroup = getGroupPermissionsGroup(groupName);

        if(permGroup == null)
            return null;

        return permGroup.getPriorityAsLong();
    }

    /**
     * Gets the priority of the group with a given name. (As an object containing long and double representations.)
     * @param groupName The name of the group to get the priority of.
     * @return The priority of the group by the given name in this permissions registry as a wrapper object containing
     *         the double and long representations of it and an indication of which it would best be represented as, or
     *         null if no such group exists.
     */
    public PermissionGroup.Priority getGroupPriorityAsObject(String groupName)
    {
        PermissionGroup permGroup = getGroupPermissionsGroup(groupName);

        if(permGroup == null)
            return null;

        return permGroup.getPriorityAsObject();
    }
    //endregion

    //region Permissions
    /**
     * <p>Gets a list of the permissions directly assigned to the specified user.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     *
     * <p>The string representations of the permissions of the user returned do not include permission arguments.</p>
     * @param userId The ID of the user to get the permissions of.
     * @return A sorted list of all permissions of the specified user, not including referenced groups or the default
     *         permissions, and not including permission arguments.
     */
    public List<String> getUserPermissions(ID userId)
    { return getPermissions(permissionsForUsers.getOrDefault(userId, null)); }

    /**
     * <p>Gets a list of the permissions directly assigned to the specified group.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     *
     * <p>The string representations of the permissions of the group returned do not include permission arguments.</p>
     * @param groupName The name of the group to get the permissions of.
     * @return A sorted list of all the permissions of the specified group, not including referenced groups or the
     *         default permissions, and not including permission arguments.
     */
    public List<String> getGroupPermissions(String groupName)
    { return getPermissions(getGroupPermissionsGroup(groupName)); }

    /**
     * <p>Gets a list of the default permissions.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include default
     * groups.</p>
     *
     * <p>The string representations of the default permissions returned do not include permission arguments.</p>
     * @return A sorted list of all the default permissions, not including default groups, and not including permission
     *         arguments.
     */
    public List<String> getDefaultPermissions()
    { return getPermissions(defaultPermissions); }

    /**
     * <p>Gets a list of string representations of all permissions directly assigned to the given permission group
     * object.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the given permission group object.</p>
     *
     * <p>The string representations returned do not include permission arguments.</p>
     * @param permGroup The permission group object to get the permissions of.
     * @return A sorted list of all permissions of the given permission group object, not including referenced groups or
     *         the default permissions, and not including permission arguments.
     */
    protected List<String> getPermissions(PermissionGroup permGroup)
    { return getPermissions(permGroup, false); }

    /**
     * <p>Gets a list of string representations of all permissions directly assigned to the given permission group
     * object.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the given permission group object.</p>
     * @param permGroup The permission group object to get the permissions of.
     * @param withArgs Whether or not to include permission arguments in the string representations of permissions.
     * @return A sorted list of all permissions of the given permission group object, not including referenced groups or
     *         the default permissions, and including permission arguments only if applicable and specified.
     */
    private List<String> getPermissions(PermissionGroup permGroup, boolean withArgs)
    {
        if(permGroup == null)
            return Collections.emptyList();

        return permGroup.getPermissionsAsStrings(withArgs);
    }

    /**
     * <p>Gets a list of the permissions directly assigned to the specified user, with arguments.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     * @param userId The ID of the user to get the permissions of.
     * @return A sorted list of all permissions of the specified user, not including referenced groups or the default
     *         permissions, and including permission arguments if applicable.
     */
    public List<String> getUserPermissionsWithArgs(ID userId)
    { return getPermissionsWithArgs(permissionsForUsers.getOrDefault(userId, null)); }

    /**
     * <p>Gets a list of the permissions directly assigned to the specified group, with arguments.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.</p>
     * @param groupName The name of the group to get the permissions of.
     * @return A sorted list of all the permissions of the specified group, not including referenced groups or the
     *         default permissions, and including permission arguments if applicable.
     */
    public List<String> getGroupPermissionsWithArgs(String groupName)
    { return getPermissionsWithArgs(getGroupPermissionsGroup(groupName)); }

    /**
     * <p>Gets a list of the default permissions, with arguments.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include default
     * groups.</p>
     * @return A sorted list of all the default permissions, not including default groups, and including permission
     *         arguments if applicable.
     */
    public List<String> getDefaultPermissionsWithArgs()
    { return getPermissionsWithArgs(defaultPermissions); }

    /**
     * <p>Gets a list of string representations of all permissions directly assigned to the given permission group
     * object, including their arguments if applicable.</p>
     *
     * <p>The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the given permission group object.</p>
     * @param permGroup The permission group object to get the permissions of.
     * @return A sorted list of all permissions of the given permission group object, not including referenced groups or
     *         the default permissions, and including permission arguments if applicable.
     */
    protected List<String> getPermissionsWithArgs(PermissionGroup permGroup)
    { return getPermissions(permGroup, true); }
    //endregion

    //region All permission statuses
    /**
     * Gets all of a user's permissions and their statuses.
     * @param userId The ID of the user.
     * @return A collection of permission statuses for all permissions of the specified user, not including referenced
     *         groups or the default permissions.
     */
    public Collection<PermissionStatus> getAllUserPermissionStatuses(ID userId)
    { return getAllPermissionsStatuses(permissionsForUsers.getOrDefault(userId, null)); }

    /**
     * Gets all of a group's permissions and their statuses.
     * @param groupName The name of the group.
     * @return A collection of permission statuses for all permissions of the specified group, not including referenced
     *         groups or the default permissions.
     */
    public Collection<PermissionStatus> getAllGroupPermissionStatuses(String groupName)
    { return getAllPermissionsStatuses(getGroupPermissionsGroup(groupName)); }

    /**
     * Gets all of the default permissions and their statuses.
     * @return A collection of permission statuses for all default permissions, not including those of default groups.
     */
    public Collection<PermissionStatus> getAllDefaultPermissionStatuses()
    { return getAllPermissionsStatuses(defaultPermissions); }

    /**
     * Gets the permissions and their status associated directly with a permission group object.
     * @param permGroup The permission group object to get the permission statuses of.
     * @return A collection of permission statuses for all permissions of the given permission group object, not
     *         including referenced groups of the default permissions.
     */
    protected Collection<PermissionStatus> getAllPermissionsStatuses(PermissionGroup permGroup)
    {
        if(permGroup == null)
            return Collections.emptyList();

        return permGroup.getPermissionStatuses();
    }
    //endregion

    //region Groups
    /**
     * Gets the names of all groups the specified user is assigned.
     * @param userId The ID of the user to get the groups of.
     * @return A list of the names of all groups the specified user is assigned, in order of group priorities from
     *         highest to lowest.
     */
    public List<String> getGroupsOfUser(ID userId)
    { return getGroupsOf(permissionsForUsers.getOrDefault(userId, null)); }

    /**
     * Gets the names of all groups the specified group is assigned.
     * @param groupId The name of the group to get the groups it's extended from.
     * @return A list of the names of all groups the specified group is assigned, in order of group priorities from
     *         highest to lowest.
     */
    public List<String> getGroupsOfGroup(String groupId)
    { return getGroupsOf(getGroupPermissionsGroup(groupId)); }

    /**
     * Gets the names of all default groups.
     * @return A list of the names of all default groups, in order of group priorities from highest to lowest.
     */
    public List<String> getDefaultGroups()
    { return getGroupsOf(defaultPermissions); }

    /**
     * Gets the names of all groups the given permission group object directly references.
     * @param permGroup The permission group object to get the referenced permission group names from.
     * @return A list of the names of all groups the given permission group object references, in order of group
     *         priorities from highest to lowest.
     */
    protected List<String> getGroupsOf(PermissionGroup permGroup)
    {
        if(permGroup == null)
            return Collections.emptyList();

        List<String> result = new ArrayList<>();

        for(PermissionGroup pg : permGroup.getPermissionGroups())
            result.add(pg.getName());

        return result;
    }
    //endregion

    //region PermissionGroups
    /**
     * Gets the permission group object of the specified group. If the group is specified as "*", this is taken to mean
     * the default permission group.
     * @param groupName The ID of the group to get the PermissionGroup object of.
     * @return The PermissionGroup object of the specified group, or the default PermissionGroup object if the group is
     *         specified as "*", or null if the specified group does not exist and is not specified as "*".
     */
    PermissionGroup getGroupPermissionsGroup(String groupName)
    { return ("*".equals(groupName)) ? (defaultPermissions) : (assignableGroups.get(groupName)); }

    /**
     * Gets the permission group object of the specified group. If the specified group does not currently exist in the
     * registry, creates it.
     * @param groupName The name of the group to get the permission group object of.
     * @return The permission group object of the group of the given name.
     * @throws InvalidGroupNameException If the group name provided is not a valid group name.
     */
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName)
    {
        if("*".equals(groupName))
            return defaultPermissions;

        assertGroupNameValid(groupName);

        return assignableGroups.computeIfAbsent(groupName, s ->
        {
            markAsModified();
            return new PermissionGroup(groupName);
        });
    }

    /**
     * Gets the permission group object of the specified group, reässigning the priority in the process. If the
     * specified group does not currently exist in the registry, creates it.
     * @param groupName The name of the group to get the permission group object of.
     * @param priority The priority to ensure the specified group has.
     * @return The permission group object of the group of the given name.
     * @throws InvalidGroupNameException If the group name provided is not a valid group name.
     */
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, long priority)
    {
        if("*".equals(groupName))
            return defaultPermissions;

        assertGroupNameValid(groupName);

        return assignableGroups.compute(groupName, (s, permissionGroup) ->
        {
            markAsModified();

            if(permissionGroup != null)
            {
                permissionGroup.reassignPriority(priority);
                return permissionGroup;
            }
            else
                return new PermissionGroup(groupName, priority);
        });
    }

    /**
     * Gets the permission group object of the specified group, reässigning the priority in the process. If the
     * specified group does not currently exist in the registry, creates it.
     * @param groupName The name of the group to get the permission group object of.
     * @param priority The priority to ensure the specified group has.
     * @return The permission group object of the group of the given name.
     * @throws InvalidGroupNameException if the group name provided is not a valid group name.
     */
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, double priority)
    {
        if("*".equals(groupName))
            return defaultPermissions;

        assertGroupNameValid(groupName);

        return assignableGroups.compute(groupName, (s, permissionGroup) ->
        {
            markAsModified();

            if(permissionGroup != null)
            {
                permissionGroup.reassignPriority(priority);
                return permissionGroup;
            }
            else
                return new PermissionGroup(groupName, priority);
        });
    }

    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, PermissionGroup.Priority priority)
    {
        return priority.isLong()
                       ? getGroupPermissionsGroupOrNew(groupName, priority.asLong())
                       : getGroupPermissionsGroupOrNew(groupName, priority.asDouble());
    }

    /**
     * Gets the permission group object of the specified group, reässigning the priority in the process. If the
     * specified group does not currently exist in the registry, creates it.
     * @param groupName The name of the group to get the permission group object of.
     * @param priorityAsString The priority to ensure the specified group has, as a string.
     * @return The permission group object of the group of the given name.
     * @throws InvalidPriorityException If the provided priority was not parsable as a number.
     * @throws InvalidGroupNameException If the provided group name was not a valid group name.
     */
    PermissionGroup getGroupPermissionsGroupOrNew(String groupName, String priorityAsString)
            throws InvalidPriorityException
    {
        if("*".equals(groupName))
            return defaultPermissions;

        long priorityAsLong = 0;
        boolean priorityIsLong = true;

        try
        { priorityAsLong = Long.parseLong(priorityAsString); }
        catch(NumberFormatException e)
        { priorityIsLong = false; }

        if(priorityIsLong)
            return getGroupPermissionsGroupOrNew(groupName, priorityAsLong);

        double priorityAsDouble = 0;
        boolean priorityIsDouble = true;

        try
        { priorityAsDouble = Double.parseDouble(priorityAsString); }
        catch(NumberFormatException e)
        { priorityIsDouble = false; }

        if(priorityIsDouble)
            return getGroupPermissionsGroupOrNew(groupName, priorityAsDouble);

        throw new InvalidPriorityException(priorityAsString);
    }

    /**
     * <p>Gets the permission group object of the specified group, making any modifications to it to bring it in line
     * with the provided save string. If the group does not currently exist in the registry, creates it.</p>
     *
     * <p>Where the provided save string includes a referenced permission group, which would have been given in the same
     * line as the name of the group being gotten, the referenced permission group is assigned to the group of the given
     * name.</p>
     * @param saveString The string representation of the group being gotten.
     * @return The permission group object of the group represented by the given save string.
     * @throws InvalidPriorityException If the provided priority was not parsable as a number.
     * @throws InvalidGroupNameException If the group name was not a valid group name.
     */
    PermissionGroup getGroupPermissionsGroupFromSaveString(String saveString)
    {
        int prioritySeparatorPosition = saveString.lastIndexOf(':');
        int groupPrefixPosition = saveString.lastIndexOf('#');

        if(groupPrefixPosition < prioritySeparatorPosition)
            groupPrefixPosition = -1;

        String superGroupName = (groupPrefixPosition < 0) ? (null) : (saveString.substring(groupPrefixPosition + 1));

        String priorityString = (prioritySeparatorPosition < 0) ? (null)
                              : (groupPrefixPosition < 0)       ? (saveString.substring(prioritySeparatorPosition + 1)
                                                                             .trim())
                              : (saveString.substring(prioritySeparatorPosition + 1, groupPrefixPosition).trim());

        String groupName = prioritySeparatorPosition > 0 ? saveString.substring(0, prioritySeparatorPosition).trim()
                         : groupPrefixPosition       > 0 ? saveString.substring(0, groupPrefixPosition).trim()
                         :                                 saveString.trim();

        if(superGroupName != null && superGroupName.isEmpty())
            superGroupName = null;

        if(priorityString != null && priorityString.isEmpty())
            priorityString = null;

        PermissionGroup result = groupName.equals("*")  ? defaultPermissions
                               : priorityString != null ? getGroupPermissionsGroupOrNew(groupName, priorityString)
                               :                          getGroupPermissionsGroupOrNew(groupName);

        if(superGroupName != null)
        {
            PermissionGroup superGroup = getGroupPermissionsGroupOrNew(superGroupName);
            assertNotCircular(result, superGroup);
            result.addPermissionGroup(superGroup);
        }

        return result;
    }

    /**
     * Gets the permission group object of the specified user. If the specified user does not currently exist in the
     * registry, registers it.
     * @param userId The ID of the user to get the permission group object of.
     * @return The permission group object of the user of the given ID.
     */
    PermissionGroup getUserPermissionsGroupOrNew(ID userId)
    {
        return permissionsForUsers.computeIfAbsent(userId, id ->
        {
            markAsModified();
            return new PermissionGroup(convertIdToString.apply(id), defaultPermissions);
        });
    }

    /**
     * <p>Gets the permission group object of the specified user, making any modifications to it to bring it in line
     * with the provided save string. If the user is not currently registered, registers them.</p>
     *
     * <p>Where the provided save string includes a referenced permission group, which would have been given in the same
     * line as the string representation of the user being gotten's ID, the referenced permission group is assigned to
     * the group of the given name.</p>
     * @param saveString The string representation of the user being gotten.
     * @return The permission group object of the user represented by the given save string.
     * @throws InvalidGroupNameException If any of the groups assigned to the user has an invalid group name.
     */
    PermissionGroup getUserPermissionsGroupFromSaveString(String saveString)
    {
        int groupPrefixPosition = saveString.lastIndexOf('#');

        String groupName = groupPrefixPosition < 0 ? null : saveString.substring(groupPrefixPosition + 1).trim();
        String userIdString = groupPrefixPosition < 0
                                      ? saveString.trim()
                                      : saveString.substring(0, groupPrefixPosition).trim();

        ID userId = parseIdFromString.apply(userIdString);
        PermissionGroup pg = getUserPermissionsGroupOrNew(userId);

        if(groupName != null && !groupName.isEmpty())
            pg.addPermissionGroup(getGroupPermissionsGroupOrNew(groupName));

        return pg;
    }
    //endregion
    //endregion
    //endregion

    //region Mutators
    //region Other registries
    //region Absorb
    /**
     * Adds the users, groups, and default permissions from another permissions registry to this one.
     * @apiNote Where the groups from the other permissions registry already exist in this one, priority will not be
     *          overridden. But priority will be copied for groups that do not currently exist in this permissions
     *          registry.
     * @param other The permissions registry to absorb the information from.
     */
    public void absorb(PermissionsRegistry<ID> other)
    {
        absorbGroups(other);
        absorbDefaults(other);
        absorbUsers(other);
        markAsModified();
    }

    /**
     * Adds the groups of another permissions registry to this one.
     * @apiNote Where groups already exist in this one, priority is not overridden.
     * @param other The permissions registry to draw groups from.
     */
    private void absorbGroups(PermissionsRegistry<ID> other)
    {
        for(String groupName : other.getGroupNames())
        {
            // Copy group priorities from other to this if they don't already exist here.
            // TO DO: Think about changing it to "if they don't already exist here OR if the current priority is 0L.
            if(!assignableGroups.containsKey(groupName))
                getGroupPermissionsGroupOrNew(groupName, other.getGroupPriorityAsObject(groupName));

            assignGroupPermissions(groupName, other.getGroupPermissionsWithArgs(groupName));
            assignGroupsToGroup(groupName, other.getGroupsOfGroup(groupName));
        }

        markAsModified();
    }

    /**
     * Adds the default permissions/groups from another permissions registry to this one.
     * @param other The permissions registry to draw default permissions/groups from.
     */
    private void absorbDefaults(PermissionsRegistry<ID> other)
    {
        assignDefaultPermissions(other.getDefaultPermissions());
        assignDefaultGroups(other.getDefaultGroups());
        markAsModified();
    }

    /**
     * Adds the users and their permissions + groups from another permissions registry to this one.
     * @param other The permissions registry to draw user information from.
     */
    private void absorbUsers(PermissionsRegistry<ID> other)
    {
        for(ID user : other.getUsers())
        {
            assignUserPermissions(user, other.getUserPermissions(user));
            assignGroupsToUser(user, other.getGroupsOfUser(user));
        }

        markAsModified();
    }
    //endregion

    //region Remove contents of

    // Is there a better name than "removeContentsOf"? Something like "Outsorb", but that isn't a word.

    /**
     * Removes the users, groups, and default permissions of another permissions registry from this one.
     * @param other The permissions registry to remove the information in this one about.
     */
    public void removeContentsOf(PermissionsRegistry<ID> other)
    {
        for(String p : other.getDefaultPermissions())
            defaultPermissions.removePermission(p);

        for(String g : other.getDefaultGroups())
            defaultPermissions.removePermissionGroup(g);

        clearUsers(other.getUsers());
        clearGroups(other.getGroupNames());
        markAsModified();
    }
    //endregion
    //endregion

    //region Permissions
    //region Assign
    //region Single
    /**
     * Assigns a permission to a user.
     * @param userId The ID of the user to assign a permission to.
     * @param permission The permission to assign.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     */
    public Permission assignUserPermission(ID userId, String permission)
    { return assignPermission(getUserPermissionsGroupOrNew(userId), permission); }

    /**
     * Assigns a permission to a group.
     * @param groupId The name of the group to assign a permission to.
     * @param permission The permission to assign.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     * @throws InvalidGroupNameException If the group name was not a valid group name.
     */
    public Permission assignGroupPermission(String groupId, String permission)
    { return assignPermission(getGroupPermissionsGroupOrNew(groupId), permission); }

    /**
     * Assigns a default permission. All users will be considered to have this permission unless otherwise overridden.
     * @param permission The permission to assign.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     */
    public Permission assignDefaultPermission(String permission)
    { return assignPermission(defaultPermissions, permission); }

    /**
     * Assigns the given permission to given permission group object.
     * @param permGroup The permission group object to assign a permission to.
     * @param permission The permission to assign to the given permission group object.
     * @return A Permission object representing the permission previously assigned, or null if there was none.
     */
    protected Permission assignPermission(PermissionGroup permGroup, String permission)
    {
        markAsModified();

        try
        { return permGroup.addPermission(permission); }
        catch(ParseException e)
        { throw new InvalidPermissionException(permission, e); }
    }
    //endregion

    //region Multiple
    /**
     * Assigns permissions to a user.
     * @param userId The ID of the user to assign permissions to.
     * @param permissions A list of permissions to assign.
     */
    public void assignUserPermissions(ID userId, List<String> permissions)
    { assignPermissions(getUserPermissionsGroupOrNew(userId), permissions); }

    /**
     * Assigns permissions to a user.
     * @param userId The ID of the user to assign permissions to.
     * @param permissions An array of permissions to assign.
     */
    public void assignUserPermissions(ID userId, String[] permissions)
    { assignUserPermissions(userId, Arrays.asList(permissions)); }

    /**
     * Assigns permissions to a group.
     * @param groupName The name of the group to assign permissions to.
     * @param permissions A list of permissions to assign.
     * @throws InvalidGroupNameException If the group name was not a valid group name.
     */
    public void assignGroupPermissions(String groupName, List<String> permissions)
    { assignPermissions(getGroupPermissionsGroupOrNew(groupName), permissions); }

    /**
     * Assigns permissions to a group.
     * @param groupName The name of the group to assign permissions to.
     * @param permissions An array of permissions to assign.
     * @throws InvalidGroupNameException If the group name was not a valid group name.
     */
    public void assignGroupPermissions(String groupName, String[] permissions)
    { assignGroupPermissions(groupName, Arrays.asList(permissions)); }

    /**
     * Assigns default permissions. All users will be considered to have these permissions unless otherwise overridden.
     * @param permissions An array of permissions to assign.
     */
    public void assignDefaultPermissions(List<String> permissions)
    { assignPermissions(defaultPermissions, permissions); }

    /**
     * Assigns default permissions. All users will be considered to have these permissions unless otherwise overridden.
     * @param permissions A list of permissions to assign.
     */
    public void assignDefaultPermissions(String[] permissions)
    { assignDefaultPermissions(Arrays.asList(permissions)); }

    /**
     * Assigns the given permissions to the given permission group object.
     * @param permGroup The permission group object to assign a permission to.
     * @param permissions A list of permissions to assign to the given permission group object.
     */
    protected void assignPermissions(PermissionGroup permGroup, List<String> permissions)
    {
        markAsModified();

        for(String p : permissions)
        {
            try
            { permGroup.addPermission(p); }
            catch(ParseException e)
            { throw new InvalidPermissionException(p, e); }
        }
    }
    //endregion
    //endregion

    //region Revoke
    //region Single
    /**
     * Removes a permission from a user.
     * @param userId The ID of the user to remove a permission from.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    public Permission revokeUserPermission(ID userId, String permission)
    { return revokePermission(permissionsForUsers.get(userId), permission); }

    /**
     * Removes a permission from a group.
     * @param groupeName The name of the group to remove a permission from.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    public Permission revokeGroupPermission(String groupeName, String permission)
    { return revokePermission(getGroupPermissionsGroup(groupeName), permission); }

    /**
     * Removes a permission from the default permissions.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    public Permission revokeDefaultPermission(String permission)
    { return revokePermission(defaultPermissions, permission); }

    /**
     * Removes the given permission from the specified permission group object.
     * @param permGroup The permission group object to remove a permission from.
     * @param permission The permission to remove.
     * @return A Permission object representing the specified permission in the permissions registry, or null if there
     *         was none. (And thus was not removed)
     */
    protected Permission revokePermission(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return null;

        markAsModified();
        return permGroup.removePermission(permission);
    }
    //endregion

    //region All
    /**
     * Removes all direct permissions from a user.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     * @param userId The ID of the user to remove all permissions from.
     */
    public void revokeAllUserPermissions(ID userId)
    { revokeAllPermissions(permissionsForUsers.get(userId)); }

    /**
     * Removes all direct permissions from a group.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     * @param groupName The name of the group to remove all permissions from.
     */
    public void revokeAllGroupPermissions(String groupName)
    { revokeAllPermissions(getGroupPermissionsGroup(groupName)); }

    /**
     * Removes all direct permissions from the default permissions.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     */
    public void revokeAllDefaultPermissions()
    { revokeAllPermissions(defaultPermissions); }

    /**
     * Removes all direct permissions from the specified permission group object.
     * @apiNote This only removes direct permissions. Groups and their permission this has indirectly will be left
     *          untouched.
     * @param permGroup The permission group object to remove all permissions from.
     */
    protected void revokeAllPermissions(PermissionGroup permGroup)
    {
        if(permGroup != null)
            permGroup.clearPermissions();

        markAsModified();
    }
    //endregion
    //endregion
    //endregion

    //region Groups
    //region Assign
    //region Single
    /**
     * Assigns a group to a user.
     * @param userId The ID of the user to assign a group to.
     * @param groupNameBeingAssigned The name of the group being assigned.
     * @throws InvalidGroupNameException If the group name was not a valid group name.
     */
    public void assignGroupToUser(ID userId, String groupNameBeingAssigned)
    { assignGroupTo(getUserPermissionsGroupOrNew(userId), groupNameBeingAssigned, false); }

    /**
     * Assigns a group to another group. A group cannot extend from itself or a group that extends from it.
     * @param groupName The name of the group to assign another group to.
     * @param groupNameBeingAssigned The name of the group being assigned.
     * @throws InvalidGroupNameException If either of the group names was not a valid group name.
     */
    public void assignGroupToGroup(String groupName, String groupNameBeingAssigned)
    { assignGroupTo(getGroupPermissionsGroupOrNew(groupName), groupNameBeingAssigned, true); }

    /**
     * Assigns a group to the default permissions.
     * @param groupNameBeingAssigned The name of the group being assigned.
     * @throws InvalidGroupNameException If the group name was not a valid group name.
     */
    public void assignDefaultGroup(String groupNameBeingAssigned)
    {  assignGroupTo(defaultPermissions, groupNameBeingAssigned, true); }

    /**
     * Assigns a group to a permission group object.
     * @param permGroup The permission group to be assigned a group.
     * @param groupNameBeingAssigned The name of the group to assign.
     * @param checkForCircular Whether or not to check for circular hierarchies.
     */
    protected void assignGroupTo(PermissionGroup permGroup, String groupNameBeingAssigned, boolean checkForCircular)
    {
        PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(groupNameBeingAssigned);

        if(checkForCircular)
            assertNotCircular(permGroup, permGroupBeingAssigned);

        permGroup.addPermissionGroup(permGroupBeingAssigned);
        markAsModified();
    }
    //endregion

    //region Multiple
    /**
     * Assigns groups to a user.
     * @param userId The ID of the user to assign groups to.
     * @param groupNamesBeingAssigned A list of the names of groups being assigned.
     * @throws InvalidGroupNameException If any of the group names were not valid group names.
     */
    public void assignGroupsToUser(ID userId, List<String> groupNamesBeingAssigned)
    { assignGroupsTo(getUserPermissionsGroupOrNew(userId), groupNamesBeingAssigned, false); }

    /**
     * Assigns groups to a user.
     * @param userId The ID of the user to assign groups to.
     * @param groupNamesBeingAssigned An array of the names of groups being assigned.
     * @throws InvalidGroupNameException If any of the group names were not valid group names.
     */
    public void assignGroupsToUser(ID userId, String[] groupNamesBeingAssigned)
    { assignGroupsToUser(userId, Arrays.asList(groupNamesBeingAssigned)); }

    /**
     * Assigns groups to another group. A group cannot extend from itself or a group that extends from it.
     * @param groupName The name of the group to assign other groups to.
     * @param groupNamesBeingAssigned A list of the names of groups being assigned.
     * @throws InvalidGroupNameException If any of the group names involved were not valid group names.
     */
    public void assignGroupsToGroup(String groupName, List<String> groupNamesBeingAssigned)
    { assignGroupsTo(getGroupPermissionsGroupOrNew(groupName), groupNamesBeingAssigned, true); }

    /**
     * Assigns groups to another group. A group cannot extend from itself or a group that extends from it.
     * @param groupName The name of the group to assign other groups to.
     * @param groupNamesBeingAssigned An array of the names of groups being assigned.
     * @throws InvalidGroupNameException If any of the group names involved were not valid group names.
     */
    public void assignGroupsToGroup(String groupName, String[] groupNamesBeingAssigned)
    { assignGroupsToGroup(groupName, Arrays.asList(groupNamesBeingAssigned)); }

    /**
     * Assigns groups to the default permissions.
     * @param groupNamesBeingAssigned A list of the names of groups being assigned.
     * @throws InvalidGroupNameException If any of the groups names were not valid group names.
     */
    public void assignDefaultGroups(List<String> groupNamesBeingAssigned)
    { assignGroupsTo(defaultPermissions, groupNamesBeingAssigned, true); }

    /**
     * Assigns groups to the default permissions.
     * @param groupNamesBeingAssigned An array of the names of groups being assigned.
     * @throws InvalidGroupNameException If any of the groups names were not valid group names.
     */
    public void assignDefaultGroups(String[] groupNamesBeingAssigned)
    { assignDefaultGroups(Arrays.asList(groupNamesBeingAssigned)); }

    /**
     * Assigns groups to a permission group object.
     * @param permGroup The permission group object to be assigned groups.
     * @param groupNamesBeingAssigned A list of the names of groups to assign.
     * @param checkForCircular Whether or not to check for circular hierarchies.
     */
    protected void assignGroupsTo(PermissionGroup permGroup,
                                  List<String> groupNamesBeingAssigned,
                                  boolean checkForCircular)
    {
        if(checkForCircular)
        {
            for(String gn : groupNamesBeingAssigned)
            {
                PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(gn);
                assertNotCircular(permGroup, permGroupBeingAssigned);
                permGroup.addPermissionGroup(permGroupBeingAssigned);
            }
        }
        else
        {
            for(String gn : groupNamesBeingAssigned)
            {
                PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(gn);
                permGroup.addPermissionGroup(permGroupBeingAssigned);
            }
        }

        markAsModified();
    }
    //endregion
    //endregion

    //region Revoke
    //region Single
    /**
     * Deässigns a group from a user.
     * @param userId The ID of the user to deässign a group from.
     * @param groupNameBeingRevoked The name of the group being deässigned.
     * @return True if a group was deässigned from the user as a result of this call. Otherwise, false.
     */
    public boolean revokeGroupFromUser(ID userId, String groupNameBeingRevoked)
    { return revokeGroupFrom(permissionsForUsers.get(userId), groupNameBeingRevoked); }

    /**
     * Deässigns a group from another group.
     * @param groupName The name of the group to deässign another group from.
     * @param groupNameBeingRevoked The name of the group to deässign.
     * @return True if a group was deässigned from the group as a result of this call. Otherwise, false.
     */
    public boolean revokeGroupFromGroup(String groupName, String groupNameBeingRevoked)
    { return revokeGroupFrom(getGroupPermissionsGroup(groupName), groupNameBeingRevoked); }

    /**
     * Deässigns a group as a default group.
     * @param groupNameBeingRevoked The group to deässign.
     * @return True if a group was deässigned as a default group as a result of this call. Otherwise, false.
     */
    public boolean revokeDefaultGroup(String groupNameBeingRevoked)
    { return revokeGroupFrom(defaultPermissions, groupNameBeingRevoked); }

    /**
     * Removes a group from the referenced groups of the given permission group object.
     * @param permGroup The permission group object to remove a referenced group from.
     * @param groupNameBeingRevoked The name of the group to remove.
     * @return True if the permission group object was modified as a result of this call. Otherwise, false.
     */
    protected boolean revokeGroupFrom(PermissionGroup permGroup, String groupNameBeingRevoked)
    {
        if(permGroup == null)
            return false;

        PermissionGroup permGroupBeingRevoked = assignableGroups.get(groupNameBeingRevoked);

        if(permGroupBeingRevoked == null)
            return false;

        markAsModified();
        return permGroup.removePermissionGroup(permGroupBeingRevoked);
    }
    //endregion

    //region All

    /**
     * Removes all groups from a user.
     * @param userId The ID of the user to remove all groups from.
     */
    public void revokeAllGroupsFromUser(ID userId)
    { revokeAllGroups(permissionsForUsers.get(userId)); }

    /**
     * Removes all groups from a group.
     * @param groupName The name of the groups to remove all groups from.
     */
    public void revokeAllGroupsFromGroup(String groupName)
    { revokeAllGroups(getGroupPermissionsGroup(groupName)); }

    /**
     * Removes all groups from the default permissions.
     */
    public void revokeAllDefaultGroups()
    { revokeAllGroups(defaultPermissions); }

    /**
     * Removes all referenced groups of the given permission group object.
     * @param permGroup The permission group object to remove all groups from.
     */
    protected void revokeAllGroups(PermissionGroup permGroup)
    {
        if(permGroup != null)
            permGroup.clearGroups();

        markAsModified();
    }
    //endregion
    //endregion
    //endregion

    //region Clear
    /**
     * Removes all users, groups, and permissions from this registry.
     */
    public void clear()
    {
        permissionsForUsers.clear();
        assignableGroups.clear();
        defaultPermissions.clear();
        markAsModified();
    }

    /**
     * Removes all users from this registry.
     */
    public void clearUsers()
    {
        permissionsForUsers.clear();
        markAsModified();
    }

    /**
     * Removes all information about the specified users from this registry.
     * @param userIds The IDs of the users to remove information about.
     */
    public void clearUsers(Collection<ID> userIds)
    {
        for(ID userId : userIds)
            permissionsForUsers.remove(userId);

        markAsModified();
    }

    /**
     * Removes all information about the specified users from this registry.
     * @param userIds The IDs of the users to remove information about.
     */
    public void clearUsers(ID[] userIds)
    {
        for(ID userId : userIds)
            permissionsForUsers.remove(userId);

        markAsModified();
    }

    /**
     * Removes all information about the specified user from this registry.
     * @param userId The ID of the user to remove information about.
     */
    public void clearUser(ID userId)
    {
        permissionsForUsers.remove(userId);
        markAsModified();
    }

    /**
     * Removes all groups from this registry. Users and the default permissions will no longer have any groups.
     */
    public void clearGroups()
    {
        assignableGroups.clear();
        defaultPermissions.clearGroups();

        for(PermissionGroup user : permissionsForUsers.values())
            user.clearGroups();

        markAsModified();
    }

    /**
     * Removes the specified groups from this registry. Users, the default permissions, and other not-specified groups
     * will no longer have any of the specified groups.
     * @param groupNames The names of the groups to remove.
     */
    public void clearGroups(Collection<String> groupNames)
    {
        Set<String> otherGroupsToCheckIfNeedingPruning = new HashSet<>();
        Collection<PermissionGroup> groupObjs = new ArrayList<>();

        for(String groupName : groupNames)
        {
            PermissionGroup groupObj = assignableGroups.remove(groupName);

            if(groupObj == null)
                continue;

            groupObjs.add(groupObj);

            otherGroupsToCheckIfNeedingPruning.addAll(groupObj.getPermissionGroups()
                                                              .stream()
                                                              .map(PermissionGroup::getName)
                                                              .collect(Collectors.toList()));
        }

        for(PermissionGroup groupObj : groupObjs)
            defaultPermissions.removePermissionGroup(groupObj);

        for(PermissionGroup user : permissionsForUsers.values())
            for(PermissionGroup groupObj : groupObjs)
                user.removePermissionGroup(groupObj);

        for(PermissionGroup otherGroup : assignableGroups.values())
        {
            boolean changed = false;

            for(PermissionGroup groupObj : groupObjs)
                changed = changed || otherGroup.removePermissionGroup(groupObj);

            if(changed && otherGroup.isEmpty())
                otherGroupsToCheckIfNeedingPruning.add(otherGroup.getName());
        }

        prune(otherGroupsToCheckIfNeedingPruning);
        markAsModified();
    }

    /**
     * Removes the specified groups from this registry. Users, the default permissions, and other not-specified groups
     * will no longer have any of the specified groups.
     * @param groupNames The names of the groups to remove.
     */
    public void clearGroups(String[] groupNames)
    { clearGroups(Arrays.asList(groupNames)); }

    /**
     * Removes the specified group from this registry. Users, the default permissions, and other not-specified groups
     * will no longer have the specified group.
     * @param groupName The name of the group to remove.
     */
    public void clearGroup(String groupName)
    {
        PermissionGroup groupObj = assignableGroups.remove(groupName);

        if(groupObj == null)
            return;

        List<String> otherGroupsToCheckIfNeedingPruning = groupObj.getPermissionGroups()
                                                                  .stream()
                                                                  .map(PermissionGroup::getName)
                                                                  .collect(Collectors.toCollection(ArrayList::new));

        defaultPermissions.removePermissionGroup(groupObj);

        for(PermissionGroup user : permissionsForUsers.values())
            user.removePermissionGroup(groupObj);

        for(PermissionGroup otherGroup : assignableGroups.values())
            if(otherGroup.removePermissionGroup(groupObj) && otherGroup.isEmpty())
                otherGroupsToCheckIfNeedingPruning.add(otherGroup.getName());

        prune(otherGroupsToCheckIfNeedingPruning);
        markAsModified();
    }

    /**
     * Removes all default permissions and groups.
     */
    public void clearDefaults()
    {
        defaultPermissions.clear();
        markAsModified();
    }

    /**
     * Removes all groups from this registry that are currently unused by any users, other groups, or the default
     * permissions, and do not have any permissions or groups themselves. That is, groups that do not functionally
     * exist in this registry, but are left over from other operations.
     */
    public void prune()
    {
        Iterator<Map.Entry<String, PermissionGroup>> iter = assignableGroups.entrySet().iterator();
        List<String> groupNamesOnlyExistentInOtherGroups = new ArrayList<>();

        for(Map.Entry<String, PermissionGroup> entry = iter.next(); iter.hasNext(); entry = iter.next())
        {
            // If the group is empty and isn't referenced by the default permissions or any users or other groups,
            // remove it.

            final String groupName = entry.getKey();

            if(   !entry.getValue().isEmpty()
               || defaultPermissions.hasGroupDirectly(groupName)
               || permissionsForUsers.values().stream().anyMatch(x -> x.hasGroupDirectly(groupName)))
            { continue; }

            if(assignableGroups.values().stream().anyMatch(x -> x.hasGroupDirectly(groupName)))
            {
                groupNamesOnlyExistentInOtherGroups.add(groupName);
                continue;
            }

            iter.remove();
        }

        // Go over groups that were only existent in other groups and remove them if they're no longer referenced by any
        // other groups. Do this repeatedly until no groups are removed.
        for(boolean groupRemoved = true; groupRemoved;)
        {
            groupRemoved = false;
            Iterator<String> groupNamesIter = groupNamesOnlyExistentInOtherGroups.iterator();

            while(groupNamesIter.hasNext())
            {
                final String groupName = groupNamesIter.next();

                if(assignableGroups.values().stream().noneMatch(x -> x.hasGroupDirectly(groupName)))
                {
                    assignableGroups.remove(groupName);
                    groupNamesIter.remove();
                    groupRemoved = true;
                }
            }
        }
    }

    /**
     * Removes the specified groups from this registry that are currently unused by any users, other groups, or the
     * default permissions, and do not have any permissions or groups themselves. That is, groups that do not
     * functionally exist in this registry, but are left over from other operations. Groups specified that *do* have any
     * permissions or other groups, or are had by any users, other groups, or the default permissions, are unaffected.
     * @param groupNames The names of the groups to remove if they match the aforementioned criteria.
     */
    public void prune(Collection<String> groupNames)
    {
        Iterator<Map.Entry<String, PermissionGroup>> iter = assignableGroups.entrySet().iterator();
        List<String> groupNamesOnlyExistentInOtherGroups = new ArrayList<>();

        for(Map.Entry<String, PermissionGroup> entry = iter.next(); iter.hasNext(); entry = iter.next())
        {
            // If the group is empty and isn't referenced by the default permissions or any users or other groups,
            // remove it.

            final String groupName = entry.getKey();

            if(!groupNames.contains(groupName))
                continue;

            if(   !entry.getValue().isEmpty()
                  || defaultPermissions.hasGroupDirectly(groupName)
                  || permissionsForUsers.values().stream().anyMatch(x -> x.hasGroupDirectly(groupName)))
            { continue; }

            if(assignableGroups.values().stream().anyMatch(x -> x.hasGroupDirectly(groupName)))
            {
                groupNamesOnlyExistentInOtherGroups.add(groupName);
                continue;
            }

            iter.remove();
        }

        // Go over groups that were only existent in other groups and remove them if they're no longer referenced by any
        // other groups. Do this repeatedly until no groups are removed.
        for(boolean groupRemoved = true; groupRemoved;)
        {
            groupRemoved = false;
            Iterator<String> groupNamesIter = groupNamesOnlyExistentInOtherGroups.iterator();

            while(groupNamesIter.hasNext())
            {
                final String groupName = groupNamesIter.next();

                if(assignableGroups.values().stream().noneMatch(x -> x.hasGroupDirectly(groupName)))
                {
                    assignableGroups.remove(groupName);
                    groupNamesIter.remove();
                    groupRemoved = true;
                }
            }
        }
    }
    //endregion

    //region Set flags
    /**
     * Marks this registry as having been modified.
     */
    protected void markAsModified()
    { hasBeenDifferentiatedFromFiles = true; }
    //endregion
    //endregion

    //region Saving & loading
    //region Saving
    /**
     * Writes reversible string representations of permission group objects to the provided writer object.
     * @param writer The writer to write to.
     * @param permGroups The permission groups to write.
     * @throws IOException If an IO exception is thrown by the provided writer.
     */
    protected static void savePerms(BufferedWriter writer, Collection<PermissionGroup> permGroups) throws IOException
    {
        Iterator<PermissionGroup> iter = permGroups.stream()
                                                   .sorted(Comparator.comparing(PermissionGroup::getName))
                                                   .iterator();

        PermissionGroup pgprevious;
        PermissionGroup pg = null;

        while(iter.hasNext())
        {
            pgprevious = pg;
            pg = iter.next();

            if(pgprevious != null)
            {
                boolean previousIsSingleLine = pgprevious.isEmpty() || pgprevious.containsOnlyAGroup();
                boolean currentIsSingleLine = pg.isEmpty() || pg.containsOnlyAGroup();
                boolean leaveBlankLine = !(previousIsSingleLine && currentIsSingleLine);

                writer.write(leaveBlankLine ? "\n\n" : "\n");
            }

            writer.write(pg.toSaveString());
        }
    }

    /**
     * Writes reversible string representations of the permissions of all users in this registry to the provided writer
     * object.
     * @param writer The writer to write to.
     * @throws IOException If an IO exception is thrown by the provided writer.
     */
    protected void saveUsers(BufferedWriter writer) throws IOException
    { savePerms(writer, permissionsForUsers.values()); }

    /**
     * Writes reversible string representations of the permissions of all groups in this registry to the provided
     * writer object.
     * @param writer The writer to write to.
     * @throws IOException If an IO exception is thrown by the provided writer.
     */
    protected void saveGroups(BufferedWriter writer) throws IOException
    {
        if(defaultPermissions.isEmpty())
        {
            savePerms(writer, assignableGroups.values());
        }
        else
        {
            savePerms(writer, Stream.concat(Stream.of(defaultPermissions),
                                            assignableGroups.values().stream())
                                    .collect(Collectors.toList()));
        }
    }

    /**
     * Writes reversible string representations of the permissions of all users in this registry to the users file.
     * @apiNote Does nothing if no users file location has been provided to the registry.
     * @throws IOException If an IO exception is thrown in the process of writing the file.
     */
    protected void saveUsers() throws IOException
    {
        if(usersFilePath == null)
            return;

        try(BufferedWriter writer = Files.newBufferedWriter(usersFilePath))
        { saveUsers(writer); }
    }

    /**
     * Writes reversible string representations of the permissions of all groups in this registry to the groups file.
     * @apiNote Does nothing if no groups file location has been provided to the registry.
     * @throws IOException If an IO exception is thrown in the process of writing the file.
     */
    protected void saveGroups() throws IOException
    {
        if(groupsFilePath == null)
            return;

        try(BufferedWriter writer = Files.newBufferedWriter(groupsFilePath))
        { saveGroups(writer); }
    }

    /**
     * <p>Gets a reversible string representation of the permissions of all users in this registry.</p>
     *
     * <p>This provides the same text as would be written to the users file upon calling {@link #saveUsers()}.</p>
     * @return A reversible string representation of the permissions of all users in this registry.
     */
    public String usersToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        { saveUsers(writer); }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    /**
     * <p>Gets a reversible string representation of the permissions of all groups in this registry.</p>
     *
     * <p>This provides the same text as would be written to the groups file upon calling {@link #saveGroups()}.</p>
     * @return A reversible string representation of the permissions of all groups in this registry.
     */
    public String groupsToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        { saveGroups(writer); }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    /**
     * Saves the contents of this registry to the files specified.
     * @apiNote Does nothing if no users or groups files have been provided to the registry.
     * @throws IOException If an IO exception is thrown in the process of writing the save files.
     */
    public void save() throws IOException
    {
        saveUsers();
        saveGroups();
        hasBeenDifferentiatedFromFiles = false;
    }
    //endregion

    //region Loading
    /**
     * Reads lines from the reader provided, parses them into permission group objects or permissions for those groups,
     * and records the information parsed.
     * @param reader The reader being read from.
     * @param createEntityFromHeader Function to create a permission group object from any particular permission
     *                               header. (e.g. group name or user ID, possibly with priority)
     * @throws IOException If an IO exception was thrown while reading from the provided reader.
     * @throws InvalidGroupNameException If any of the groups to be assigned to a permission group objects has an
     *                                   invalid name.
     */
    private void loadPerms(PermissionsLineReader reader,
                             Function<String, PermissionGroup> createEntityFromHeader,
                             boolean isForGroups)
            throws IOException
    {
        PermissionGroup currentPermGroup = null;
        markAsModified();

        for(String line; (line = reader.readLine()) != null;)
        {
            if(line.startsWith(" "))
            {
                if(currentPermGroup == null)
                    continue;

                line = line.trim();

                if(line.startsWith("#"))
                {
                    PermissionGroup groupToAssign = getGroupPermissionsGroupOrNew(line.substring(1).trim());

                    if(isForGroups)
                        assertNotCircular(currentPermGroup, groupToAssign);

                    currentPermGroup.addPermissionGroup(groupToAssign);
                    continue;
                }

                try
                { currentPermGroup.addPermissionWhileDeIndenting(line); }
                catch(ParseException e)
                { throw new InvalidPermissionException(line, e); }
            }
            else if(!(line.trim().isEmpty()))
                currentPermGroup = createEntityFromHeader.apply(line);
        }
    }

    /**
     * <p>Reads users and their permissions from the provided reader.</p>
     *
     * <p>Does not clear registered users first.</p>
     * @param reader The reader to read from.
     * @throws IOException If an IO exception was thrown while reading from the provided reader.
     * @throws InvalidGroupNameException If any of the groups assigned to users have invalid names.
     */
    private void loadUsers(PermissionsLineReader reader) throws IOException
    { loadPerms(reader, this::getUserPermissionsGroupFromSaveString, false); }

    /**
     * <p>Reads groups and their permissions from the provided reader.</p>
     *
     * <p>Does not clear registered groups first.</p>
     * @param reader The reader to read from.
     * @throws IOException If an IO exception was thrown while reading from the provided reader.
     * @throws InvalidGroupNameException If any of the groups loaded or any groups added to them have invalid names.
     */
    private void loadGroups(PermissionsLineReader reader) throws IOException
    { loadPerms(reader, this::getGroupPermissionsGroupFromSaveString, false); }

    /**
     * <p>Reads the users file, and loads read user records and permissions into the registry.</p>
     *
     * <p>Does nothing if there is no users file specified or if the users file cannot be read.</p>
     *
     * <p>Does not clear registered users first.</p>
     * @throws IOException If an IO exception was thrown while reading the users file.
     * @throws InvalidGroupNameException If any of the groups assigned to users have invalid names.
     */
    protected void loadUsers() throws IOException
    {
        if((usersFilePath == null) || (!Files.isReadable(usersFilePath)) || (Files.isDirectory(usersFilePath)))
            return;

        try(PermissionsLineReader reader = new PermissionsLineReader(Files.newBufferedReader(usersFilePath)))
        { loadUsers(reader); }
    }

    /**
     * <p>Reads the groups file, and loads read group records and permissions into the registry.</p>
     *
     * <p>Does nothing if there is no groups file specified or if the groups file cannot be read.</p>
     *
     * <p>Does not clear registered groups first.</p>
     * @throws IOException If an IO exception was thrown while reading the groups file.
     * @throws InvalidGroupNameException If any of the groups loaded or any groups added to them have invalid names.
     */
    protected void loadGroups() throws IOException
    {
        if((groupsFilePath == null) || (!Files.isReadable(groupsFilePath)) || (Files.isDirectory(groupsFilePath)))
            return;

        try(PermissionsLineReader reader = new PermissionsLineReader(Files.newBufferedReader(groupsFilePath)))
        { loadGroups(reader); }
    }

    /**
     * <p>Reads the provided save string, and loads read user records and permissions into the registry.</p>
     *
     * <p>The string provided should contain information in the same format as would be produced by
     * {@link #usersToSaveString()}.</p>
     *
     * <p>Does not clear registered users first.</p>
     * @param saveString The string to read.
     * @throws IOException If an IO exception was thrown while reading from the provided save string.
     * @throws InvalidGroupNameException If any of the groups assigned to users have invalid names.
     */
    protected void loadUsersFromSaveString(String saveString) throws IOException
    {
        try(PermissionsLineReader reader = new PermissionsLineReader(new BufferedReader(new StringReader(saveString))))
        { loadUsers(reader); }
    }

    /**
     * <p>Reads the provided save string, and loads read group records and permissions into the registry.</p>
     *
     * <p>The string provided should contain information in the same format as would be produced by
     * {@link #groupsToSaveString()}.</p>
     *
     * <p>Does not clear registered groups first.</p>
     * @param saveString The string to read.
     * @throws IOException If an IO exception was thrown while reading from the provided save string.
     * @throws InvalidGroupNameException If any of the groups loaded or any groups added to them have invalid names.
     */
    protected void loadGroupsFromSaveString(String saveString) throws IOException
    {
        try(PermissionsLineReader reader = new PermissionsLineReader(new BufferedReader(new StringReader(saveString))))
        { loadGroups(reader); }
    }

    /**
     * <p>Clears the registry and loads information from the users and groups files.</p>
     *
     * <p>Does nothing if the users and groups files have not been specified or cannot be read from.</p>
     * @throws IOException If an IO exception was thrown while reading from the users or groups files.
     * @throws InvalidGroupNameException If any of the groups loaded or assigned to any group or user have invalid
     *                                   names.
     */
    public void load() throws IOException
    {
        clear();
        loadGroups();
        loadUsers();
        hasBeenDifferentiatedFromFiles = false;
    }
    //endregion
    //endregion
    //endregion
}
