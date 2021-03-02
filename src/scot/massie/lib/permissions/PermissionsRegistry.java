package scot.massie.lib.permissions;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A registry for assigning permissions to users in a system and checking them.
 *
 * Users may be assigned permissions to indicate allowance to do something, or to provide some level of per-user
 * configurability.
 *
 * Permissions are provided as dot-separated alphanumeric strings. (e.g. "first.second.third") A permission is said to
 * "cover" another permission where the other permission starts with the dot-separated sections ("nodes") of the first,
 * in order. (e.g. "first.second.third" covers "first.second.third.fourth", but not "first.second.fourth" or
 * "second.first.third.fourth") A permission does not cover another where the other starts with the first, but doesn't
 * have the first's last node exactly. (e.g. "first.second.thi" does not cover "first.second.third" or
 * "first.second.third.fourth")
 *
 * The "most relevant permission" a user has to a given permission is the permission the user has that covers the
 * given permission with the most number of nodes.
 *
 * Users may be assigned "Groups", which are referred to by name, as strings. Groups may have their own permissions and
 * may be assigned other groups. Groups may also have "priorities" (numbers) associated with them. Where a user or group
 * does not have a given permission, it then checks the groups it is assigned, in order of priority from highest to
 * lowest, to see if they cover the given permission.
 *
 * A default "*" group may be defined with permissions and/or groups, which all users are considered to have assigned to
 * them. This may be thought of as a lowest priority group associated with all users.
 *
 * Permissions may be prefixed with a "-" to indicate that a user does *not* have the given permission, that that
 * permission is negated. If the most relevant permission to a given permission a user or group has is negating, that
 * user or group is considered not to have the given permission.
 *
 * Permissions may be suffixed with a ".*" to indicate that they cover permissions longer than it, but not the
 * permission itself. ("first.second.*" covers "first.second.third", but not "first.second")
 *
 * Permissions may be followed by (after any suffixes) a colon (":") and any arbitrary string. This string is the
 * "permission argument". When getting the permission argument of a given permission, it returns the argument of the
 * most relevant permission. Permission arguments may be multiple lines.
 * @param <ID> The type of the unique identifier used to represent users.
 */
public class PermissionsRegistry<ID extends Comparable<? super ID>>
{
    //region inner static classes
    //region exceptions

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

        protected String permissionString;

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

        final String invalidPriority;

        /**
         * Gets the string that cannot be read as a number, which caused this exception.
         * @return The string that cannot be read as a number, which caused this exception.
         */
        public String getInvalidPriority()
        { return invalidPriority; }
    }
    //endregion

    //region text parsing

    /**
     * Reader for parsing text in the registry's save string format.
     *
     * Primarily exists to merge multiple lines that make up on logical line in a save string into single lines
     * possibly containing newline characters.
     *
     * A line in this sense may make up multiple actual lines where a permission is spread across multiple lines - e.g.
     * where a permission has a multi-line permission argument.
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
         * Reads lines from the contained reader without considering logical lines that may span across multiple actual
         * lines.
         *
         * Has the side effect of setting {@link #lastLineReadDumblyHadStringArg} when reading a line containing a
         * permission argument, so that it can be determined by {@link #readLine()} whether the multiple actual lines
         * are part of the same logical line.
         * @return The next line, or null if there are no more lines.
         * @throws IOException If an IO exception is thrown by the contained reader in the process of reading from it.
         */
        private String readLineDumbly() throws IOException
        {
            StringBuilder sb = new StringBuilder();
            boolean elligableForStringArg = false;
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
                    elligableForStringArg = true;

                if((elligableForStringArg) && (c == ':'))
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

            while(((nextLine = readLineDumbly()) != null) && ((lineIndentLevel + 4) <= getIndentLevel(nextLine)))
                line += "\n" + nextLine.substring(lineIndentLevel);

            heldOverLine = nextLine;
            return line;
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

    //region initialisation

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
    {
        this.convertIdToString = idToString;
        this.parseIdFromString = idFromString;
        this.usersFilePath = usersFile;
        this.groupsFilePath = groupsFile;
    }

    /**
     * Creates a new permissions registry without the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public PermissionsRegistry(Function<ID, String> idToString,
                               Function<String, ID> idFromString)
    {
        this.convertIdToString = idToString;
        this.parseIdFromString = idFromString;
        this.usersFilePath = null;
        this.groupsFilePath = null;
    }
    //endregion

    //region instance variables

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
    protected final PermissionGroup defaultPermissions = new PermissionGroup("*");


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

    //region methods
    //region accessors
    //region permission queries
    //region has

    /**
     * Checks whether or not a given user "has" a given permission.
     *
     * That is, checks whether the given user's permissions contains (directly, via a group it's assigned, or via the
     * default permissions) at least one permission that covers the given permission, and whether the most relevant
     * permission of the given user to the given permission is an allowing permission. (as opposed to a negating
     * permission.)
     * @param userId The user to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the user has the given permission as defined above. Otherwise, false.
     */
    public boolean userHasPermission(ID userId, String permission)
    { return hasPermission(permissionsForUsers.get(userId), permission, true); }

    /**
     * Checks whether or not a given group "has" a given permission.
     *
     * That is, checks whether the given group's permissions contains (directly or via a group it extends from, but not
     * via the default permissions) at least one permission that covers the given permission, and whether the most
     * relevant permission of the given group to the given permission is an allowing permission. (as opposed to a
     * negating permission.)
     * @param groupId The name of the group to check whether or not they have the given permission.
     * @param permission The permission to check for.
     * @return True if the group has the given permission as defined above. Otherwise, false.
     */
    public boolean groupHasPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return hasDefaultPermission(permission);

        return hasPermission(assignableGroups.get(groupId), permission, false);
    }

    /**
     * Checks whether or not the default permissions "has" a given permission.
     *
     * That is, checks whether the default permissions contains (directly or via a group assigned as a default group) at
     * least one permission that covers the given permission, and whether the most relevant permission of the default
     * permissions is an allowing permission. (as opposed to a negating permission.)
     * @param permission The permission to check for.
     * @return True if the default permissions has the given permission as defined above. Otherwise, false.
     */
    public boolean hasDefaultPermission(String permission)
    { return hasPermission(defaultPermissions, permission, false); }

    /**
     * Checks whether or not a given permission group object "has" a given permission.
     *
     * That is, checks whether the given permission group object contains (directly or via another referenced permission
     * group object) a permission that covers the given permission, and if so, whether the most relevant permission to
     * the given one is allowing.
     * @param permGroup The permission group object to check for the allowance of the given permission.
     * @param permission The permission to check for.
     * @param deferToDefault Whether or not to defer to the default permission group object where the given permision
     *                       group object is null.
     * @return True if any of the following are true:
     *
     *         <ul>
     *             <il>
     *                 All of the following are true:
     *                 <ul>
     *                     <il>The given permission group object is non-null.</il>
     *                     <il>
     *                         It, or any other permission group objects it references, (which may or may not include
     *                         the default permission group object) contains a permission that covers the given
     *                         permission.
     *                     </il>
     *                     <il>The most relevant permission within the given permission group is an allowing one.</il>
     *                 </ul>
     *             </il>
     *             <il>The given permission group object is null and deferToDefault is true.</il>
     *         </ul>
     */
    private boolean hasPermission(PermissionGroup permGroup, String permission, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault ? defaultPermissions.hasPermission(permission) : false;

        return permGroup.hasPermission(permission);
    }
    //endregion

    //region args

    /**
     * Gets the argument associated with the given permission for the given user.
     *
     * That is, where a given user has a permission as described in {@link #userHasPermission(Comparable, String)} and
     * where the most relevant permission a user has to the given permission has a permission argument associated,
     * returns that argument. Otherwise, returns null.
     * @param userId The user to get the permission argument from.
     * @param permission The permission to get the permission argument of.
     * @return If the user has the given permission and the most relevant permission the user has to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    public String getUserPermissionArg(ID userId, String permission)
    { return getPermissionArg(permissionsForUsers.get(userId), permission, true); }

    /**
     * Gets the argument associated with the given permission for the given group.
     *
     * That is, where a given group has a permission as described in {@link #groupHasPermission(String, String)} and
     * where the most relevant permission a group has to the given permission has a permission argument associated,
     * returns that argument. Otherwise, returns null.
     * @param groupId The name of the group to get the permission argument from.
     * @param permission The permission to get the permission argument of.
     * @return If the group has the given permission and the most relevant permission the group has to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    public String getGroupPermissionArg(String groupId, String permission)
    {
        if("*".equals(groupId))
            return getDefaultPermissionArg(permission);

        return getPermissionArg(assignableGroups.get(groupId), permission, false);
    }

    /**
     * Gets the argument associated with the given permission in the default permissions.
     *
     * That is, where the default permissions has a permission as described in {@link #hasDefaultPermission(String)} and
     * where the most relevant default permission to the given permissions has a permission argument associated, returns
     * that argument. Otherwise, returns null.
     * @param permission The permission to get the permission argument of.
     * @return If the default permissions has the given permission and the most relevant default permission to the given
     *         permission has a permission argument associated, that permission argument. Otherwise, null.
     */
    public String getDefaultPermissionArg(String permission)
    { return defaultPermissions.getPermissionArg(permission); }

    /**
     * Gets the permission argument associated with the given permission for the given permission group object, or null
     * if there is none.
     *
     * That is, where a user has a given permission as described in
     * {@link #hasPermission(PermissionGroup, String, boolean)} and where the most relevant permission has a permission
     * argument associated, returns that permission argument. Otherwise, returns null. Returns null if the most relevant
     * permission to the given permission a permission group object has has no permission argument associated with it,
     * even where another permission that covers it does.
     * @param permGroup The permission group object to get a permission argument from.
     * @param permission The permission to get the permission argument of.
     * @param deferToDefault Whether or not to defer to the default permissions where the given permission group object
     *                       is null.
     * @return The string argument associated with the most relevant permission to the given permission in the given
     *         permission group, or null if the given permission group doesn't have that permission, or if the most
     *         relevant permission doesn't have a permission argument associated.
     */
    private String getPermissionArg(PermissionGroup permGroup, String permission, boolean deferToDefault)
    {
        if(permGroup == null)
            return deferToDefault ? defaultPermissions.getPermissionArg(permission) : null;

        return permGroup.getPermissionArg(permission);
    }
    //endregion
    //endregion

    //region group queries

    /**
     * Gets whether or not the given user is assigned a group with the given name. (directly, via an assigned group, or
     * via the default permissions.)
     * @param userId The user to check whether or not they have the specified group.
     * @param groupId The name of the group to check whether or not the user has.
     * @return True if the user, any group assigned to the user, or the default permissions, has a group by the given
     *         name. Otherwise, false.
     */
    public boolean userHasGroup(ID userId, String groupId)
    { return hasGroup(permissionsForUsers.get(userId), groupId, true); }

    /**
     * Gets whether or not one group with the specified name is assigned another, by the other specified name.
     * (directly or via another assigned group, but not via the default permissions.)
     * @param groupId The name of the group to check whether it extends from the other group specified.
     * @param superGroupId The name of the group to check whether the other group specifies it.
     * @return True if the group or any group assigned to the group (that is, that the group is extended from), has a
     *         group assigned to it by the given name. Otherwise, false.
     */
    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    {
        if("*".equals(groupId))
            return isDefaultGroup(superGroupId);

        return hasGroup(assignableGroups.get(groupId), superGroupId, false);
    }

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
     * @return True if any of the following are true:
     *
     *         <ul>
     *             <il>
     *                 The given permission group object is non-null and it or any of the groups it references directly
     *                 or indirectly (which may or may not include the default permission group object) references the
     *                 a permission group by the specified name.
     *             </il>
     *             <il>
     *                 The given permission group object is null, deferToDefault is true, and the default permission
     *                 group object, directly or indirectly, extends from a group with the specified name.
     *             </il>
     *         </ul>
     *
     *         Otherwise, false.
     */
    private boolean hasGroup(PermissionGroup permGroup, String groupId, boolean deferToDefault)
    {
        if(permGroup == null)
            return false;

        return permGroup.hasGroup(groupId);
    }
    //endregion

    //region check general state

    /**
     * Gets whether or not the permissions registry has had its values modified since the last time it was saved or
     * loaded.
     * @return True if the permissions registry has been modified since being saved or loaded. Otherwise, false.
     */
    public boolean hasBeenDifferentiatedFromFiles()
    { return hasBeenDifferentiatedFromFiles; }
    //endregion

    //region getters
    //region members

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
    //endregion

    //region permissions

    /**
     * Gets a list of the permissions directly assigned to the specified user.
     *
     * The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.
     *
     * The string representations of the permissions of the user returned do not include permission arguments.
     * @param userId The ID of the user to get the permissions of.
     * @return A sorted list of all permissions of the specified user, not including assigned groups, and not including
     *         permission arguments.
     */
    public List<String> getUserPermissions(ID userId)
    { return getPermissions(permissionsForUsers.getOrDefault(userId, null)); }

    /**
     * Gets a list of the permissions directly assigned to the specified group.
     *
     * The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the user.
     *
     * The string representations of the permissions of the group returned do not include permission arguments.
     * @param groupdId The name of the group to get the permissions of.
     * @return A sorted list of all the permissions of the specified group, not including assigned groups, and not
     *         including permission arguments.
     */
    public List<String> getGroupPermissions(String groupdId)
    {
        if("*".equals(groupdId))
            return getDefaultPermissions();

        return getPermissions(assignableGroups.getOrDefault(groupdId, null));
    }

    /**
     * Gets a list of the default permissions.
     *
     * The resulting list is ordered by the nodes of the permissions alphabetically, and does not include default
     * groups.
     *
     * The string representations of the default permissions returned do not include permission arguments.
     * @return A sorted list of all the default permissions, not including default groups, and not including permission
     *         arguments.
     */
    public List<String> getDefaultPermissions()
    { return getPermissions(defaultPermissions); }

    /**
     * Gets a list of string representations of all permissions directly assigned to the given permission group object.
     *
     * The resulting list is ordered by the nodes of the permissions alphabetically, and does not include groups
     * assigned to the given permission group object.
     *
     * The string representations returned do not include permission arguments.
     * @param permGroup The permission group object to get the permissions of.
     * @return A sorted list of all permissions of the given permissions group object, not including assigned groups,
     *         and not including permission arguments.
     */
    private List<String> getPermissions(PermissionGroup permGroup)
    {
        if(permGroup == null)
            return Collections.emptyList();

        return permGroup.getPermissionsAsStrings(false);
    }
    //endregion

    //region groups

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
    {
        if("*".equals(groupId))
            return getDefaultGroups();

        return getGroupsOf(assignableGroups.getOrDefault(groupId, null));
    }

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
    private List<String> getGroupsOf(PermissionGroup permGroup)
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
     * Gets the permission group object of the specified group. If the specified group does not currently exist in the
     * registry, creates it.
     * @param groupId The name of the group to get the permission group object of.
     * @return The permission group object of the group of the given name.
     */
    PermissionGroup getGroupPermissionsGroup(String groupId)
    {
        return assignableGroups.computeIfAbsent(groupId, s ->
        {
            markAsModified();
            return new PermissionGroup(groupId);
        });
    }

    /**
     * Gets the permission group object of the specified group, reässigning the priority in the process. If the
     * specified group does not currently exist in the registry, creates it.
     * @param groupId The name of the group to get the permission group object of.
     * @param priority The priority to ensure the specified group has.
     * @return The permission group object of the group of the given name.
     */
    PermissionGroup getGroupPermissionsGroup(String groupId, long priority)
    {
        return assignableGroups.compute(groupId, (s, permissionGroup) ->
        {
            markAsModified();

            if(permissionGroup != null)
            {
                permissionGroup.reassignPriority(priority);
                return permissionGroup;
            }
            else
                return new PermissionGroup(groupId, priority);
        });
    }

    /**
     * Gets the permission group object of the specified group, reässigning the priority in the process. If the
     * specified group does not currently exist in the registry, creates it.
     * @param groupId The name of the group to get the permission group object of.
     * @param priority The priority to ensure the specified group has.
     * @return The permission group object of the group of the given name.
     */
    PermissionGroup getGroupPermissionsGroup(String groupId, double priority)
    {
        return assignableGroups.compute(groupId, (s, permissionGroup) ->
        {
            markAsModified();

            if(permissionGroup != null)
            {
                permissionGroup.reassignPriority(priority);
                return permissionGroup;
            }
            else
                return new PermissionGroup(groupId, priority);
        });
    }

    /**
     * Gets the permission group object of the specified group, reässigning the priority in the process. In the
     * specified group does not currently exist in the registry, creates it.
     * @param groupId The name of the group to get the permission group object of.
     * @param priorityAsString The priority to ensure the specified group has, as a string.
     * @return The permission group object of the group of the given name.
     * @throws InvalidPriorityException If the provided priority was not parsable as a number.
     */
    PermissionGroup getGroupPermissionsGroup(String groupId, String priorityAsString) throws InvalidPriorityException
    {
        long priorityAsLong = 0;
        boolean priorityIsLong = true;

        try
        { priorityAsLong = Long.parseLong(priorityAsString); }
        catch(NumberFormatException e)
        { priorityIsLong = false; }

        if(priorityIsLong)
            return getGroupPermissionsGroup(groupId, priorityAsLong);

        double priorityAsDouble = 0;
        boolean priorityIsDouble = true;

        try
        { priorityAsDouble = Double.parseDouble(priorityAsString); }
        catch(NumberFormatException e)
        { priorityIsDouble = false; }

        if(priorityIsDouble)
            return getGroupPermissionsGroup(groupId, priorityAsDouble);

        throw new InvalidPriorityException(priorityAsString);
    }

    /**
     * Gets the permission group object of the specified group, making any modifications to it to bring it in line with
     * the provided save string. If the group does not currently exist in the registry, creates it.
     *
     * Where the provided save string includes a referenced permission group, which would have been given in the same
     * line as the name of the group being gotten, the referenced permission group is assigned to the group of the given
     * name.
     * @param saveString The string representation of the group being gotten.
     * @return The permission group object of the group represented by the given save string.
     */
    PermissionGroup getGroupPermissionsGroupFromSaveString(String saveString)
    {
        int prioritySeparatorPosition = saveString.lastIndexOf(':');
        int groupPrefixPosition = saveString.lastIndexOf('#');

        if(groupPrefixPosition < prioritySeparatorPosition)
            groupPrefixPosition = -1;

        String superGroupName = (groupPrefixPosition < 0) ? (null) : (saveString.substring(groupPrefixPosition + 1));

        String priorityString = (prioritySeparatorPosition < 0) ? (null)
                              : (groupPrefixPosition < 0)       ? (saveString.substring(prioritySeparatorPosition + 1).trim())
                              : (saveString.substring(prioritySeparatorPosition + 1, groupPrefixPosition).trim());

        String groupName = prioritySeparatorPosition > 0 ? saveString.substring(0, prioritySeparatorPosition).trim()
                         : groupPrefixPosition       > 0 ? saveString.substring(0, groupPrefixPosition).trim()
                         :                                 saveString.trim();

        if(superGroupName != null && superGroupName.isEmpty())
            superGroupName = null;

        if(priorityString != null && priorityString.isEmpty())
            priorityString = null;

        PermissionGroup result = groupName.equals("*")  ? defaultPermissions
                               : priorityString != null ? getGroupPermissionsGroup(groupName, priorityString)
                               :                          getGroupPermissionsGroup(groupName);

        if(superGroupName != null)
            result.addPermissionGroup(getGroupPermissionsGroup(superGroupName));

        return result;
    }

    /**
     * Gets the permission group object of the specified user. In the specified user does not currently exist in the
     * registry, registers it.
     * @param userId The ID of the user to get the permission group object of.
     * @return The permission group object of the user of the given ID.
     */
    PermissionGroup getUserPermissionsGroup(ID userId)
    {
        return permissionsForUsers.computeIfAbsent(userId, id ->
        {
            markAsModified();
            return new PermissionGroup(convertIdToString.apply(id), defaultPermissions);
        });
    }

    /**
     * Gets the permission group object of the specified user, making any modifications to it to bring it in line with
     * the provided save string. If the user is not currently registered, registers them.
     *
     * Where the provided save string includes a referenced permission group, which would have been given in the same
     * line as the string representation of the user being gotten's ID, the referenced permission group is assigned to
     * the group of the given name.
     * @param saveString The string representation of the user being gotten.
     * @return The permission group object of the user represented by the given save string.
     */
    PermissionGroup getUserPermissionsGroupFromSaveString(String saveString)
    {
        int groupPrefixPosition = saveString.lastIndexOf('#');

        String groupName = groupPrefixPosition < 0 ? null : saveString.substring(groupPrefixPosition + 1).trim();
        String userIdString = saveString.substring(0, groupPrefixPosition).trim();
        ID userId = parseIdFromString.apply(userIdString);

        PermissionGroup pg = groupName.equals("*") ? defaultPermissions : getUserPermissionsGroup(userId);

        if(!groupName.isEmpty())
            pg.addPermissionGroup(getGroupPermissionsGroup(groupName));

        return pg;
    }
    //endregion
    //endregion
    //endregion

    //region mutators
    //region permissions
    //region assign

    /**
     * Assigns a permission to a user.
     * @param userId The ID of the user to assign a permission to.
     * @param permission The permission to assign.
     */
    public void assignUserPermission(ID userId, String permission)
    { assignPermission(getUserPermissionsGroup(userId), permission); }

    /**
     * Assigns a permission to a group.
     * @param groupId The name of the group to assign a permission to.
     * @param permission The permission to assign.
     */
    public void assignGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            assignDefaultPermission(permission);
        else
            assignPermission(getGroupPermissionsGroup(groupId), permission);
    }

    /**
     * Assigns a default permission. All users will be considered to have this permission unless otherwise overridden.
     * @param permission The permission to assign.
     */
    public void assignDefaultPermission(String permission)
    { assignPermission(defaultPermissions, permission); }

    /**
     * Assigns the given permission to given permission group object.
     * @param permGroup The permission group object to assign a permission to.
     * @param permission The permission to assign to the given permission group object.
     */
    private void assignPermission(PermissionGroup permGroup, String permission)
    {
        markAsModified();

        try
        { permGroup.addPermission(permission); }
        catch(ParseException e)
        { throw new InvalidPermissionException(permission, e); }
    }
    //endregion

    //region revoke

    /**
     * Removes a permission from a user.
     * @param userId The ID of the user to remove a permission from.
     * @param permission The permission to remove.
     * @return True if a permission was removed as a result of this call. Otherwise, false.
     */
    public boolean revokeUserPermission(ID userId, String permission)
    { return revokePermission(permissionsForUsers.get(userId), permission); }

    /**
     * Removes a permission from a group.
     * @param groupId The name of the group to remove a permission from.
     * @param permission The permission to remove.
     * @return True if a permission was removed as a result of this call. Otherwise, false.
     */
    public boolean revokeGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return revokeDefaultPermission(permission);

        return revokePermission(assignableGroups.get(groupId), permission);
    }

    /**
     * Removes a permission from the default permissions.
     * @param permission The permission to remove.
     * @return True if a permission was removed as a result of this call. Otherwise, false.
     */
    public boolean revokeDefaultPermission(String permission)
    { return revokePermission(defaultPermissions, permission); }

    /**
     * Removes the given permission from the specified permission group object.
     * @param permGroup The permission group object to remove a permission from.
     * @param permission The permission to remove.
     * @return True if the permission group object was modified as a result of this call. Otherwise, false.
     */
    private boolean revokePermission(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return false;

        markAsModified();
        return permGroup.removePermission(permission);
    }
    //endregion
    //endregion

    //region groups
    //region assign

    /**
     * Assigns a group to a user.
     * @param userId The ID of the user to assign a group to.
     * @param groupIdBeingAssigned The name of the group being assigned.
     */
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    { getUserPermissionsGroup(userId).addPermissionGroup(getGroupPermissionsGroup(groupIdBeingAssigned)); }

    /**
     * Assigns a group to another group.
     * @param groupId The name of the group to assign another group to.
     * @param groupIdBeingAssigned The name of the group being assigned.
     */
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        if("*".equals(groupId))
            assignDefaultGroup(groupIdBeingAssigned);
        else
            getGroupPermissionsGroup(groupId).addPermissionGroup(getGroupPermissionsGroup(groupIdBeingAssigned));
    }

    /**
     * Assigns a group to the default permissions.
     * @param groupIdBeingAssigned The name of the group being assigned.
     */
    public void assignDefaultGroup(String groupIdBeingAssigned)
    { defaultPermissions.addPermissionGroup(getGroupPermissionsGroup(groupIdBeingAssigned)); }
    //endregion

    //region revoke

    /**
     * Deässigns a group from a user.
     * @param userId The ID of the user to deässign a group from.
     * @param groupIdBeingRevoked The name of the group being deässigned.
     * @return True if a group was deässigned from the user as a result of this call. Otherwise, false.
     */
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    { return revokeGroupFrom(permissionsForUsers.get(userId), groupIdBeingRevoked); }

    /**
     * Deässigns a group from another group.
     * @param groupId The name of the group to deässign another group from.
     * @param groupIdBeingRevoked The name of the group to deässign.
     * @return True if a group was deässigned from the group as a result of this call. Otherwise, false.
     */
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        if("*".equals(groupId))
            return revokeDefaultGroup(groupIdBeingRevoked);

        return revokeGroupFrom(assignableGroups.get(groupId), groupIdBeingRevoked);
    }

    /**
     * Deässigns a group as a default group.
     * @param groupIdBeingRevoked The group to deässign.
     * @return True if a group was deässigned as a default group as a result of this call. Otherwise, false.
     */
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    { return revokeGroupFrom(defaultPermissions, groupIdBeingRevoked); }

    /**
     * Removes a group from the referenced groups of the given permission group object.
     * @param permGroup The permission group object to remove a referenced group from.
     * @param groupIdBeingRevoked The name of the group to remove.
     * @return True if the permission group object was modified as a result of this call. Otherwise, false.
     */
    private boolean revokeGroupFrom(PermissionGroup permGroup, String groupIdBeingRevoked)
    {
        if(permGroup == null)
            return false;

        PermissionGroup permGroupBeingRevoked = assignableGroups.get(groupIdBeingRevoked);

        if(permGroupBeingRevoked == null)
            return false;

        markAsModified();
        return permGroup.removePermissionGroup(permGroupBeingRevoked);
    }
    //endregion
    //endregion

    //region clear

    /**
     * Removes all users, groups, and permissions from this registry.
     */
    public void clear()
    {
        permissionsForUsers.clear();
        assignableGroups.clear();
        defaultPermissions.clear();
    }
    //endregion

    //region set flags

    /**
     * Marks this registry as having been modified.
     */
    protected void markAsModified()
    { hasBeenDifferentiatedFromFiles = true; }
    //endregion
    //endregion

    //region saving & loading
    //region saving

    /**
     * Writes reversible string representations of permission group objects to the provided writer object.
     * @param writer The writer to write to.
     * @param permGroups The permission groups to write.
     * @throws IOException If an IO exception is thrown by the provided writer.
     */
    private static void savePerms(BufferedWriter writer, Collection<PermissionGroup> permGroups) throws IOException
    {
        Iterator<PermissionGroup> iter = permGroups.stream()
                                                   .sorted(Comparator.comparing(PermissionGroup::getName))
                                                   .iterator();

        PermissionGroup pgprevious = null, pg = null;

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
     * Gets a reversible string representation of the permissions of all users in this registry.
     *
     * This provides the same text as would be written to the users file upon calling {@link #saveUsers()}.
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
     * Gets a reversible string representation of the permissions of all groups in this registry.
     *
     * This provides the same text as would be written to the groups file upon calling {@link #saveGroups()}.
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

    //region loading

    /**
     * Reads lines from the reader provided, parses them into permission groups or permissions for those groups, and
     * records the information parsed.
     * @param reader The reader being read from.
     * @param createEntityFromHeader Function to create a permission group object from any particular permission
     *                               header. (e.g. group name or user ID, possibly with priority)
     * @throws IOException If an IO exception was thrown while reading from the provided reader.
     */
    private void loadPerms(PermissionsLineReader reader, Function<String, PermissionGroup> createEntityFromHeader) throws IOException
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
                    currentPermGroup.addPermissionGroup(getGroupPermissionsGroup(line.substring(1).trim()));
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
     * Reads users and their permissions from the provided reader.
     *
     * Does not clear registered users first.
     * @param reader The reader to read from.
     * @throws IOException If an IO exception was thrown while reading from the provided reader.
     */
    protected void loadUsers(PermissionsLineReader reader) throws IOException
    { loadPerms(reader, this::getUserPermissionsGroupFromSaveString); }

    /**
     * Reads groups and their permissions from the provided reader.
     *
     * Does not clear registered groups first.
     * @param reader The reader to read from.
     * @throws IOException If an IO exception was thrown while reading from the provided reader.
     */
    protected void loadGroups(PermissionsLineReader reader) throws IOException
    { loadPerms(reader, this::getGroupPermissionsGroupFromSaveString); }

    /**
     * Reads the users file, and loads read user records and permissions into the registry.
     *
     * Does nothing if there is no users file specified or if the users file cannot be read.
     *
     * Does not clear registered users first.
     * @throws IOException If an IO exception was thrown while reading the users file.
     */
    protected void loadUsers() throws IOException
    {
        if((usersFilePath == null) || (!Files.isReadable(usersFilePath)) || (Files.isDirectory(usersFilePath)))
            return;

        try(PermissionsLineReader reader = new PermissionsLineReader(Files.newBufferedReader(usersFilePath)))
        { loadUsers(reader); }
    }

    /**
     * Reads the groups file, and loads read group records and permissions into the registry.
     *
     * Does nothing if there is no groups file specified or if the groups file cannot be read.
     *
     * Does not clear registered groups first.
     * @throws IOException If an IO exception was thrown while reading the groups file.
     */
    protected void loadGroups() throws IOException
    {
        if((groupsFilePath == null) || (!Files.isReadable(groupsFilePath)) || (Files.isDirectory(groupsFilePath)))
            return;

        try(PermissionsLineReader reader = new PermissionsLineReader(Files.newBufferedReader(groupsFilePath)))
        { loadGroups(reader); }
    }

    /**
     * Reads the provided save string, and loads read user records and permissions into the registry.
     *
     * The string provided should contain information in the same format as would be produced by
     * {@link #usersToSaveString()}.
     *
     * Does not clear registered users first.
     * @param saveString The string to read.
     * @throws IOException If an IO exception was thrown while reading from the provided save string.
     */
    protected void loadUsersFromSaveString(String saveString) throws IOException
    {
        try(PermissionsLineReader reader = new PermissionsLineReader(new BufferedReader(new StringReader(saveString))))
        { loadUsers(reader); }
    }

    /**
     * Reads the provided save string, and loads read group records and permissions into the registry.
     *
     * The string provided should contain information in the same format as would be produced by
     * {@link #groupsToSaveString()}.
     *
     * Does not clear registered groups first.
     * @param saveString The string to read.
     * @throws IOException If an IO exception was thrown while reading from the provided save string.
     */
    protected void loadGroupsFromSaveString(String saveString) throws IOException
    {
        try(PermissionsLineReader reader = new PermissionsLineReader(new BufferedReader(new StringReader(saveString))))
        { loadGroups(reader); }
    }

    /**
     * Clears the registry and loads information from the users and groups files.
     *
     * Does nothing if the users and groups files have not been specified or cannot be read from.
     * @throws IOException If an IO exception was thrown while reading from the users or groups files.
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
