package scot.massie.lib.permissions;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class PermissionsRegistry<ID extends Comparable<? super ID>>
{
    public static class PermissionsRegistryException extends RuntimeException
    {
        public PermissionsRegistryException() { super(); }
        public PermissionsRegistryException(String message) { super(message); }
        public PermissionsRegistryException(Throwable cause) { super(cause); }
        public PermissionsRegistryException(String message, Throwable cause) { super(message, cause); }
    }

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

        public String getPermissionString()
        { return permissionString; }
    }

    public static class InvalidPriorityException extends NumberFormatException
    {
        public InvalidPriorityException(String invalidPriority)
        {
            super("Invalid permission group priority: " + invalidPriority);
            this.invalidPriority = invalidPriority;
        }

        final String invalidPriority;

        public String getInvalidPriority()
        { return invalidPriority; }
    }

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

    public PermissionsRegistry(Function<ID, String> idToString,
                               Function<String, ID> idFromString)
    {
        this.convertIdToString = idToString;
        this.parseIdFromString = idFromString;
        this.usersFilePath = null;
        this.groupsFilePath = null;
    }

    final Map<ID, PermissionGroup> permissionsForUsers = new HashMap<>();
    final Map<String, PermissionGroup> assignableGroups = new HashMap<>();

    final Function<ID, String> convertIdToString;
    final Function<String, ID> parseIdFromString;

    final Path usersFilePath;
    final Path groupsFilePath;

    private PermissionGroup getOrCreateUserPerms(ID userId)
    { return permissionsForUsers.computeIfAbsent(userId, id -> new PermissionGroup(convertIdToString.apply(id))); }

    private PermissionGroup getOrCreatePermGroup(String groupId)
    { return assignableGroups.computeIfAbsent(groupId, PermissionGroup::new); }

    public void assignUserPermission(ID userId, String permission)
    { assignPermission(getOrCreateUserPerms(userId), permission); }

    public void assignGroupPermission(String groupId, String permission)
    { assignPermission(getOrCreatePermGroup(groupId), permission); }

    private void assignPermission(PermissionGroup permGroup, String permission)
    {
        try
        { permGroup.addPermission(permission); }
        catch(ParseException e)
        { throw new InvalidPermissionException(permission, e); }
    }

    public boolean revokeUserPermission(ID userId, String permission)
    { return revokePermission(permissionsForUsers.get(userId), permission); }

    public boolean revokeGroupPermission(String groupId, String permission)
    { return revokePermission(assignableGroups.get(groupId), permission); }

    private boolean revokePermission(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return false;

        return permGroup.removePermission(permission);
    }

    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    { getOrCreateUserPerms(userId).addPermissionGroup(getOrCreatePermGroup(groupIdBeingAssigned)); }

    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    { getOrCreatePermGroup(groupId).addPermissionGroup(getOrCreatePermGroup(groupIdBeingAssigned)); }

    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    { return revokeGroupFrom(permissionsForUsers.get(userId), groupIdBeingRevoked); }

    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    { return revokeGroupFrom(assignableGroups.get(groupId), groupIdBeingRevoked); }

    private boolean revokeGroupFrom(PermissionGroup permGroup, String groupIdBeingRevoked)
    {
        if(permGroup == null)
            return false;

        PermissionGroup permGroupBeingRevoked = assignableGroups.get(groupIdBeingRevoked);

        if(permGroupBeingRevoked == null)
            return false;

        return permGroup.removePermissionGroup(permGroupBeingRevoked);
    }

    public boolean userHasPermission(ID userId, String permission)
    { return hasPermission(permissionsForUsers.get(userId), permission); }

    public boolean groupHasPermission(String groupId, String permission)
    { return hasPermission(assignableGroups.get(groupId), permission); }

    private boolean hasPermission(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return false;

        return permGroup.hasPermission(permission);
    }

    public String getUserPermissionArg(ID userId, String permission)
    { return getPermissionArg(permissionsForUsers.get(userId), permission); }

    public String getGroupPermissionArg(String groupId, String permission)
    { return getPermissionArg(assignableGroups.get(groupId), permission); }

    private String getPermissionArg(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return null;

        return permGroup.getPermissionArg(permission);
    }

    public PermissionGroup createGroup(String groupId)
    { return assignableGroups.computeIfAbsent(groupId, s -> new PermissionGroup(groupId)); }

    public PermissionGroup createGroup(String groupId, long priority)
    { return assignableGroups.computeIfAbsent(groupId, s -> new PermissionGroup(groupId, priority)); }

    public PermissionGroup createGroup(String groupId, double priority)
    { return assignableGroups.computeIfAbsent(groupId, s -> new PermissionGroup(groupId, priority)); }

    public PermissionGroup createGroup(String groupId, String priorityAsString)
    {
        long priorityAsLong = 0;
        boolean priorityIsLong = true;

        try
        { priorityAsLong = Long.parseLong(priorityAsString); }
        catch(NumberFormatException e)
        { priorityIsLong = false; }

        if(priorityIsLong)
            return createGroup(groupId, priorityAsLong);

        double priorityAsDouble = 0;
        boolean priorityIsDouble = true;

        try
        { priorityAsDouble = Double.parseDouble(priorityAsString); }
        catch(NumberFormatException e)
        { priorityIsDouble = false; }

        if(priorityIsDouble)
            return createGroup(groupId, priorityAsDouble);

        throw new InvalidPriorityException(priorityAsString);
    }

    private PermissionGroup createGroupFromSaveString(String saveString)
    {
        int prioritySeparatorPosition = saveString.lastIndexOf(":");

        if(prioritySeparatorPosition < 0)
            return createGroup(saveString.trim());

        String groupId = saveString.substring(0, prioritySeparatorPosition);
        String priority = saveString.substring(prioritySeparatorPosition + 1);
        return createGroup(groupId, priority);
    }

    public PermissionGroup createUserPermissions(ID userId)
    { return permissionsForUsers.computeIfAbsent(userId, id -> new PermissionGroup(convertIdToString.apply(id))); }

    private PermissionGroup createUserPermissionsFromSaveString(String saveString)
    { return createUserPermissions(parseIdFromString.apply(saveString.trim())); }

    public void clear()
    {
        permissionsForUsers.clear();
        assignableGroups.clear();
    }

    //region Saving & Loading
    //region Saving
    void savePerms(BufferedWriter writer, Collection<PermissionGroup> permGroups) throws IOException
    {
        Iterator<PermissionGroup> iter = permGroups.stream()
                                                   .sorted(Comparator.comparing(PermissionGroup::getName))
                                                   .iterator();

        while(iter.hasNext())
        {
            writer.write(iter.next().toSaveString());

            if(iter.hasNext())
                writer.write("\n\n");
        }
    }

    void saveUsers(BufferedWriter writer) throws IOException
    { savePerms(writer, permissionsForUsers.values()); }

    void saveGroups(BufferedWriter writer) throws IOException
    { savePerms(writer, assignableGroups.values()); }

    void saveUsers() throws IOException
    {
        if(usersFilePath == null)
            return;

        try(BufferedWriter writer = Files.newBufferedWriter(usersFilePath))
        { saveUsers(writer); }
    }

    void saveGroups() throws IOException
    {
        if(groupsFilePath == null)
            return;

        try(BufferedWriter writer = Files.newBufferedWriter(groupsFilePath))
        { saveGroups(writer); }
    }

    String usersToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        { saveUsers(writer); }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    String groupsToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        { saveGroups(writer); }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    public void save() throws IOException
    {
        saveUsers();
        saveGroups();
    }
    //endregion

    //region Loading
    void loadUsers(BufferedReader reader) throws IOException
    {
        ID currentUser = null;

        for(String line; (line = reader.readLine()) != null;)
        {
            if(line.startsWith(" "))
            {
                if(currentUser == null)
                    continue;

                line = line.trim();

                if(line.startsWith("#"))
                {
                    assignGroupToUser(currentUser, line.substring(1).trim());
                    continue;
                }

                assignUserPermission(currentUser, line);
            }
            else
                currentUser = parseIdFromString.apply(createUserPermissionsFromSaveString(line).getName());
        }
    }

    void loadGroups(BufferedReader reader) throws IOException
    {
        PermissionGroup currentGroup = null;

        for(String line; (line = reader.readLine()) != null;)
        {
            if(line.startsWith(" "))
            {
                if(currentGroup == null)
                    continue;

                line = line.trim();

                if(line.startsWith("#"))
                {
                    assignGroupToGroup(currentGroup.getName(), line.substring(1).trim());
                    continue;
                }

                assignGroupPermission(currentGroup.getName(), line);
            }
            else
                currentGroup = createGroupFromSaveString(line);
        }
    }

    void loadUsers() throws IOException
    {
        if(usersFilePath == null)
            return;

        try(BufferedReader reader = Files.newBufferedReader(usersFilePath))
        { loadUsers(reader); }
    }

    void loadGroups() throws IOException
    {
        if(groupsFilePath == null)
            return;

        try(BufferedReader reader = Files.newBufferedReader(groupsFilePath))
        { loadGroups(reader); }
    }

    void loadUsersFromSaveString(String saveString) throws IOException
    {
        try(BufferedReader reader = new BufferedReader(new StringReader(saveString)))
        { loadUsers(reader); }
    }

    void loadGroupsFromSaveString(String saveString) throws IOException
    {
        try(BufferedReader reader = new BufferedReader((new StringReader((saveString)))))
        { loadGroups(reader); }
    }

    public void load() throws IOException
    {
        clear();
        loadGroups();
        loadUsers();
    }
    //endregion
    //endregion
}
