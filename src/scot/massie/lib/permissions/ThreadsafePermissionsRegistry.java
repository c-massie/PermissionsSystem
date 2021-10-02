package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.*;
import java.util.function.Function;

public class ThreadsafePermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    public ThreadsafePermissionsRegistry(Function<ID, String> idToString,
                                         Function<String, ID> idFromString,
                                         Path usersFile,
                                         Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    public ThreadsafePermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    protected PermissionGroup getPermissionGroupForUser(ID userId)
    {
        synchronized(permissionsForUsers)
        { return permissionsForUsers.get(userId); }
    }

    protected PermissionGroup getPermissionGroupForUserOrNull(ID userId)
    {
        synchronized(permissionsForUsers)
        { return permissionsForUsers.getOrDefault(userId, null); }
    }

    protected PermissionGroup getPermissionGroupForGroup(String groupId)
    {
        synchronized(assignableGroups)
        { return assignableGroups.get(groupId); }
    }

    protected PermissionGroup getPermissionGroupForGroupOrNull(String groupId)
    {
        synchronized(assignableGroups)
        { return assignableGroups.getOrDefault(groupId, null); }
    }



    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { return getPermissionStatus(getPermissionGroupForUser(userId), permission, true); }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupId, String permission)
    { return getPermissionStatus(getPermissionGroupForGroup(groupId), permission, false); }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    { return hasPermission(getPermissionGroupForUser(userId), permission, true); }

    @Override
    public boolean groupHasPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return isDefaultPermission(permission);

        return hasPermission(getPermissionGroupForGroup(groupId), permission, false);
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { return hasAnySubPermissionOf(getPermissionGroupForUser(userId), permission, true); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    {
        if("*".equals(groupId))
            return isOrAnySubPermissionOfIsDefault(permission);

        return hasAnySubPermissionOf(getPermissionGroupForGroup(groupId), permission, false);
    }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    { return getPermissionArg(getPermissionGroupForUser(userId), permission, true); }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    {
        if("*".equals(groupId))
            return getDefaultPermissionArg(permission);

        return getPermissionArg(getPermissionGroupForGroup(groupId), permission, false);
    }

    @Override
    public boolean userHasGroup(ID userId, String groupId)
    { return hasGroup(getPermissionGroupForUser(userId), groupId, true); }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    {
        if("*".equals(groupId))
            return isDefaultGroup(superGroupId);

        return hasGroup(getPermissionGroupForGroup(groupId), superGroupId, false);
    }

    @Override
    public Collection<String> getGroupNames()
    { synchronized(assignableGroups) { return new HashSet<>(assignableGroups.keySet()); } }

    @Override
    public Collection<ID> getUsers()
    { synchronized(assignableGroups) { return new HashSet<>(permissionsForUsers.keySet()); } }

    @Override
    public List<String> getUserPermissions(ID userId)
    { return getPermissions(getPermissionGroupForUserOrNull(userId)); }

    @Override
    public List<String> getGroupPermissions(String groupdId)
    {
        if("*".equals(groupdId))
            return getDefaultPermissions();

        return getPermissions(getPermissionGroupForGroup(groupdId));
    }

    @Override
    public List<String> getGroupsOfUser(ID userId)
    { return getGroupsOf(getPermissionGroupForUserOrNull(userId)); }

    @Override
    public List<String> getGroupsOfGroup(String groupId)
    {
        if("*".equals(groupId))
            return getDefaultGroups();

        return getGroupsOf(getPermissionGroupForGroup(groupId));
    }

    @Override
    public void assignUserPermission(ID userId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assignGroupPermission(String groupId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assignDefaultPermission(String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected void assignPermission(PermissionGroup permGroup, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean revokeUserPermission(ID userId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean revokeGroupPermission(String groupId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean revokeDefaultPermission(String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected boolean revokePermission(PermissionGroup permGroup, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assignDefaultGroup(String groupIdBeingAssigned)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected void assignGroupTo(PermissionGroup permGroup, String groupIdBeingAssigned, boolean checkForCircular)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected boolean revokeGroupFrom(PermissionGroup permGroup, String groupIdBeingRevoked)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void clear()
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected void saveUsers() throws IOException
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected void saveGroups() throws IOException
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected void loadUsers() throws IOException
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected void loadGroups() throws IOException
    { throw new UnsupportedOperationException("Not implemented yet."); }
}
