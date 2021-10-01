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

    protected PermissionGroup getPermissionGroupForGroup(String groupId)
    {
        synchronized(assignableGroups)
        { return assignableGroups.get(groupId); }
    }



    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public PermissionStatus getDefaultPermissionStatus(String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected PermissionStatus getPermissionStatus(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assertUserHasPermission(ID userId, String permission) throws UserMissingPermissionException
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assertGroupHasPermission(String groupName, String permission) throws GroupMissingPermissionException
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public void assertIsDefaultPermission(String permission) throws PermissionNotDefaultException
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean groupHasPermission(String groupId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean isDefaultPermission(String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected boolean hasPermission(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean isOrAnySubPermissionOfIsDefault(String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected boolean hasAnySubPermissionOf(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public String getDefaultPermissionArg(String permission)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected String getPermissionArg(PermissionGroup permGroup, String permission, boolean deferToDefault)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean userHasGroup(ID userId, String groupId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public boolean isDefaultGroup(String groupId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected boolean hasGroup(PermissionGroup permGroup, String groupId, boolean deferToDefault)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public Collection<String> getGroupNames()
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public Collection<ID> getUsers()
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public List<String> getUserPermissions(ID userId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public List<String> getGroupPermissions(String groupdId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public List<String> getDefaultPermissions()
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected List<String> getPermissions(PermissionGroup permGroup)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public List<String> getGroupsOfUser(ID userId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public List<String> getGroupsOfGroup(String groupId)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    public List<String> getDefaultGroups()
    { throw new UnsupportedOperationException("Not implemented yet."); }

    @Override
    protected List<String> getGroupsOf(PermissionGroup permGroup)
    { throw new UnsupportedOperationException("Not implemented yet."); }

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
