package scot.massie.lib.permissions;

import java.nio.file.Path;
import java.text.ParseException;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Function;

public class PermissionsRegistry<ID extends Comparable<? super ID>>
{
    public PermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString, Path filePath)
    {
        this.convertIdToString = idToString;
        this.parseIdFromString = idFromString;
        this.filePath = filePath;
    }

    public PermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    {
        this.convertIdToString = idToString;
        this.parseIdFromString = idFromString;
        this.filePath = null;
    }

    final Map<ID, PermissionGroup> permissionsForUsers = new HashMap<>();
    final Map<String, PermissionGroup> assignableGroups = new HashMap<>();

    final Function<ID, String> convertIdToString;
    final Function<String, ID> parseIdFromString;

    final Path filePath;

    private PermissionGroup getOrCreateUserPerms(ID userId)
    { return permissionsForUsers.computeIfAbsent(userId, id -> new PermissionGroup("User permissions for: " + convertIdToString.apply(id))); }

    private PermissionGroup getOrCreatePermGroup(String groupId)
    { return assignableGroups.computeIfAbsent(groupId, PermissionGroup::new); }

    public void assignUserPermission(ID userId, String permission)
    {
        try
        { getOrCreateUserPerms(userId).addPermission(permission); }
        catch(ParseException e)
        { System.err.println("Invalid permission: " + permission + "\n -> " + e.getMessage()); }
    }

    public void assignGroupPermission(String groupId, String permission)
    {
        try
        { getOrCreatePermGroup(groupId).addPermission(permission); }
        catch(ParseException e)
        { System.err.println("Invalid permission: " + permission + "\n -> " + e.getMessage()); }
    }

    public void revokeUserPermission(ID userId, String permission)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public void revokeGroupPermission(String groupId, String permission)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public boolean assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        PermissionGroup groupToBeAssigned = assignableGroups.get(groupIdBeingAssigned);

        if(groupToBeAssigned == null)
            return false;

        getOrCreateUserPerms(userId).addPermissionGroup(groupToBeAssigned);
        return true;
    }

    public boolean assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        PermissionGroup groupToBeAssigned = assignableGroups.get(groupIdBeingAssigned);
        PermissionGroup groupToBeAssignedTo = assignableGroups.get(groupId);

        if(groupToBeAssigned == null || groupToBeAssignedTo == null)
            return false;

        groupToBeAssignedTo.addPermissionGroup(groupToBeAssigned);
        return true;
    }

    public void revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public void revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public boolean userHasPermission(ID userId, String permission)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public boolean groupHasPermission(String groupId, String permission)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public String getUserPermissionArg(ID userId, String permission)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public String getGroupPermissionArg(String groupId, String permission)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public void clear()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public String toSaveString()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public String loadFromSaveString(String saveString)
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public void save()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    public void load()
    {
        throw new UnsupportedOperationException("Not implemented yet.");
    }
}
