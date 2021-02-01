package scot.massie.lib.permissions;

import java.nio.file.Path;
import java.text.ParseException;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Function;

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

    public void clear()
    {
        permissionsForUsers.clear();
        assignableGroups.clear();
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
