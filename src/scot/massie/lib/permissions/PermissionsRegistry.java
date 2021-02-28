package scot.massie.lib.permissions;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PermissionsRegistry<ID extends Comparable<? super ID>>
{
    //region inner static classes
    //region exceptions
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
    //endregion

    //region text parsing
    private static class PermissionsLineReader extends Reader
    {
        public PermissionsLineReader(Reader source)
        { this.source = source; }

        private final Reader source;
        private String heldOverLine = null;
        private boolean lastLineReadDumblyHadStringArg = false;

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
    //endregion

    //region instance variables
    final Map<ID, PermissionGroup> permissionsForUsers = new HashMap<>();
    final Map<String, PermissionGroup> assignableGroups = new HashMap<>();

    PermissionGroup defaultPermissions = new PermissionGroup("*");

    final Function<ID, String> convertIdToString;
    final Function<String, ID> parseIdFromString;

    final Path usersFilePath;
    final Path groupsFilePath;

    boolean hasBeenDifferentiatedFromFiles = false;
    //endregion

    //region methods
    //region accessors
    //region permission queries
    //region has
    public boolean userHasPermission(ID userId, String permission)
    { return hasPermission(permissionsForUsers.get(userId), permission); }

    public boolean groupHasPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return hasDefaultPermission(permission);

        return hasPermission(assignableGroups.get(groupId), permission);
    }

    public boolean hasDefaultPermission(String permission)
    { return hasPermission(defaultPermissions, permission); }

    private boolean hasPermission(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return defaultPermissions.hasPermission(permission);

        return permGroup.hasPermission(permission);
    }
    //endregion

    //region args
    public String getUserPermissionArg(ID userId, String permission)
    { return getPermissionArg(permissionsForUsers.get(userId), permission); }

    public String getGroupPermissionArg(String groupId, String permission)
    {
        if("*".equals(groupId))
            return getDefaultPermissionArg(permission);

        return getPermissionArg(assignableGroups.get(groupId), permission);
    }

    public String getDefaultPermissionArg(String permission)
    { return defaultPermissions.getPermissionArg(permission); }

    private String getPermissionArg(PermissionGroup permGroup, String permission)
    {
        if(permGroup == null)
            return defaultPermissions.getPermissionArg(permission);

        return permGroup.getPermissionArg(permission);
    }
    //endregion
    //endregion

    //region group queries
    public boolean userHasGroup(ID userId, String groupId)
    { return hasGroup(permissionsForUsers.get(userId), groupId); }

    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    {
        if("*".equals(groupId))
            return isDefaultGroup(superGroupId);

        return hasGroup(assignableGroups.get(groupId), superGroupId);
    }

    public boolean isDefaultGroup(String groupId)
    { return hasGroup(defaultPermissions, groupId); }

    private boolean hasGroup(PermissionGroup permGroup, String groupId)
    {
        if(permGroup == null)
            return false;

        return permGroup.hasGroup(groupId);
    }
    //endregion

    //region check general state
    public boolean hasBeenDifferentiatedFromFiles()
    { return hasBeenDifferentiatedFromFiles; }
    //endregion

    //region getters
    //region members
    public Collection<String> getGroupNames()
    { return new HashSet<>(assignableGroups.keySet()); }

    public Collection<ID> getUsers()
    { return new HashSet<>(permissionsForUsers.keySet()); }
    //endregion

    //region permissions
    public List<String> getUserPermissions(ID userId)
    { return getPermissions(permissionsForUsers.getOrDefault(userId, null)); }

    public List<String> getGroupPermissions(String groupdId)
    {
        if("*".equals(groupdId))
            return getDefaultPermissions();

        return getPermissions(assignableGroups.getOrDefault(groupdId, null));
    }

    public List<String> getDefaultPermissions()
    { return getPermissions(defaultPermissions); }

    private List<String> getPermissions(PermissionGroup permGroup)
    {
        if(permGroup == null)
            return Collections.emptyList();

        return permGroup.getPermissionsAsStrings(false);
    }
    //endregion

    //region groups
    public List<String> getGroupsOfUser(ID userId)
    { return getGroupsOf(permissionsForUsers.getOrDefault(userId, null)); }

    public List<String> getGroupsOfGroup(String groupId)
    {
        if("*".equals(groupId))
            return getDefaultGroups();

        return getGroupsOf(assignableGroups.getOrDefault(groupId, null));
    }

    public List<String> getDefaultGroups()
    { return getGroupsOf(defaultPermissions); }

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
    //endregion
    //endregion

    //region accessors with initialisation
    private PermissionGroup getOrCreateUserPerms(ID userId)
    {
        return permissionsForUsers.computeIfAbsent(userId, id ->
        {
            markAsModified();
            return new PermissionGroup(convertIdToString.apply(id), defaultPermissions);
        });
    }

    private PermissionGroup getOrCreatePermGroup(String groupId)
    {
        return assignableGroups.computeIfAbsent(groupId, name ->
        {
            markAsModified();
            return new PermissionGroup(name);
        });
    }

    PermissionGroup createGroup(String groupId)
    {
        return assignableGroups.computeIfAbsent(groupId, s ->
        {
            markAsModified();
            return new PermissionGroup(groupId);
        });
    }

    PermissionGroup createGroup(String groupId, long priority)
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

    PermissionGroup createGroup(String groupId, double priority)
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

    PermissionGroup createGroup(String groupId, String priorityAsString)
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

    PermissionGroup createGroupFromSaveString(String saveString)
    {
        int prioritySeparatorPosition = saveString.lastIndexOf(':');
        int groupPrefixPosition = saveString.lastIndexOf('#');

        if(groupPrefixPosition < prioritySeparatorPosition)
            groupPrefixPosition = -1;

        String superGroupName = (groupPrefixPosition < 0) ? (null) : (saveString.substring(groupPrefixPosition + 1));

        String priorityString = (prioritySeparatorPosition < 0) ? (null)
                                        : (groupPrefixPosition < 0) ? (saveString.substring(prioritySeparatorPosition + 1).trim())
                                                  : (saveString.substring(prioritySeparatorPosition + 1, groupPrefixPosition).trim());

        String groupName = prioritySeparatorPosition > 0 ? saveString.substring(0, prioritySeparatorPosition).trim()
                                   : groupPrefixPosition       > 0 ? saveString.substring(0, groupPrefixPosition).trim()
                                             :                                 saveString.trim();

        if(superGroupName != null && superGroupName.isEmpty())
            superGroupName = null;

        if(priorityString != null && priorityString.isEmpty())
            priorityString = null;

        PermissionGroup result = groupName.equals("*")  ? defaultPermissions
                                         : priorityString != null ? createGroup(groupName, priorityString)
                                                   :                          createGroup(groupName);

        if(superGroupName != null)
            result.addPermissionGroup(getOrCreatePermGroup(superGroupName));

        return result;
    }

    PermissionGroup createUserPermissions(ID userId)
    {
        return permissionsForUsers.computeIfAbsent(userId, id ->
        {
            markAsModified();
            return new PermissionGroup(convertIdToString.apply(id), defaultPermissions);
        });
    }

    PermissionGroup createUserPermissionsFromSaveString(String saveString)
    {
        int groupPrefixPosition = saveString.lastIndexOf('#');

        String groupName = groupPrefixPosition < 0 ? null : saveString.substring(groupPrefixPosition + 1).trim();
        String userIdString = saveString.substring(0, groupPrefixPosition).trim();
        ID userId = parseIdFromString.apply(userIdString);

        PermissionGroup pg = groupName.equals("*") ? defaultPermissions : createUserPermissions(userId);

        if(!groupName.isEmpty())
            pg.addPermissionGroup(getOrCreatePermGroup(groupName));

        return pg;
    }
    //endregion

    //region mutators
    //region permissions
    //region assign
    public void assignUserPermission(ID userId, String permission)
    { assignPermission(getOrCreateUserPerms(userId), permission); }

    public void assignGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            assignDefaultPermission(permission);
        else
            assignPermission(getOrCreatePermGroup(groupId), permission);
    }

    public void assignDefaultPermission(String permission)
    { assignPermission(defaultPermissions, permission); }

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
    public boolean revokeUserPermission(ID userId, String permission)
    { return revokePermission(permissionsForUsers.get(userId), permission); }

    public boolean revokeGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return revokeDefaultPermission(permission);

        return revokePermission(assignableGroups.get(groupId), permission);
    }

    public boolean revokeDefaultPermission(String permission)
    { return revokePermission(defaultPermissions, permission); }

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
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    { getOrCreateUserPerms(userId).addPermissionGroup(getOrCreatePermGroup(groupIdBeingAssigned)); }

    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        if("*".equals(groupId))
            assignDefaultGroup(groupIdBeingAssigned);
        else
            getOrCreatePermGroup(groupId).addPermissionGroup(getOrCreatePermGroup(groupIdBeingAssigned));
    }

    public void assignDefaultGroup(String groupIdBeingAssigned)
    { defaultPermissions.addPermissionGroup(getOrCreatePermGroup(groupIdBeingAssigned)); }
    //endregion

    //region revoke
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    { return revokeGroupFrom(permissionsForUsers.get(userId), groupIdBeingRevoked); }

    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        if("*".equals(groupId))
            return revokeDefaultGroup(groupIdBeingRevoked);

        return revokeGroupFrom(assignableGroups.get(groupId), groupIdBeingRevoked);
    }

    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    { return revokeGroupFrom(defaultPermissions, groupIdBeingRevoked); }

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
    public void clear()
    {
        permissionsForUsers.clear();
        assignableGroups.clear();
        defaultPermissions.clear();
    }
    //endregion

    //region set flags
    protected void markAsModified()
    { hasBeenDifferentiatedFromFiles = true; }
    //endregion
    //endregion

    //region saving & loading
    //region saving
    void savePerms(BufferedWriter writer, Collection<PermissionGroup> permGroups) throws IOException
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

    void saveUsers(BufferedWriter writer) throws IOException
    { savePerms(writer, permissionsForUsers.values()); }

    void saveGroups(BufferedWriter writer) throws IOException
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
        hasBeenDifferentiatedFromFiles = false;
    }
    //endregion

    //region loading
    void loadPerms(PermissionsLineReader reader, Function<String, PermissionGroup> createEntityFromHeader) throws IOException
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
                    currentPermGroup.addPermissionGroup(getOrCreatePermGroup(line.substring(1).trim()));
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

    void loadUsers(PermissionsLineReader reader) throws IOException
    { loadPerms(reader, this::createUserPermissionsFromSaveString); }

    void loadGroups(PermissionsLineReader reader) throws IOException
    { loadPerms(reader, this::createGroupFromSaveString); }

    void loadUsers() throws IOException
    {
        if((usersFilePath == null) || (!Files.isReadable(usersFilePath)) || (Files.isDirectory(usersFilePath)))
            return;

        try(PermissionsLineReader reader = new PermissionsLineReader(Files.newBufferedReader(usersFilePath)))
        { loadUsers(reader); }
    }

    void loadGroups() throws IOException
    {
        if((groupsFilePath == null) || (!Files.isReadable(groupsFilePath)) || (Files.isDirectory(groupsFilePath)))
            return;

        try(PermissionsLineReader reader = new PermissionsLineReader(Files.newBufferedReader(groupsFilePath)))
        { loadGroups(reader); }
    }

    void loadUsersFromSaveString(String saveString) throws IOException
    {
        try(PermissionsLineReader reader = new PermissionsLineReader(new BufferedReader(new StringReader(saveString))))
        { loadUsers(reader); }
    }

    void loadGroupsFromSaveString(String saveString) throws IOException
    {
        try(PermissionsLineReader reader = new PermissionsLineReader(new BufferedReader(new StringReader(saveString))))
        { loadGroups(reader); }
    }

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
