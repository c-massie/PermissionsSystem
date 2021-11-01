package scot.massie.lib.permissions;

import scot.massie.lib.utils.wrappers.MutableWrapper;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.function.Function;

public class ThreadsafePermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    protected final Object mainSyncLock = new Object();

    public ThreadsafePermissionsRegistry(Function<ID, String> idToString,
                                         Function<String, ID> idFromString,
                                         Path usersFile,
                                         Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    public ThreadsafePermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    {
        synchronized(mainSyncLock)
        { return getPermissionStatus(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupId, String permission)
    {
        synchronized(mainSyncLock)
        { return getPermissionStatus(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    {
        synchronized(mainSyncLock)
        { return hasPermission(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public boolean groupHasPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return isDefaultPermission(permission);

        synchronized(mainSyncLock)
        { return hasPermission(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    {
        synchronized(mainSyncLock)
        { return hasAnySubPermissionOf(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    {
        if("*".equals(groupId))
            return isOrAnySubPermissionOfIsDefault(permission);

        synchronized(mainSyncLock)
        { return hasAnySubPermissionOf(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    {
        synchronized(mainSyncLock)
        { return getPermissionArg(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    {
        if("*".equals(groupId))
            return getDefaultPermissionArg(permission);

        synchronized(mainSyncLock)
        { return getPermissionArg(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public boolean userHasGroup(ID userId, String groupId)
    {
        synchronized(mainSyncLock)
        { return hasGroup(permissionsForUsers.get(userId), groupId, true); }
    }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    {
        if("*".equals(groupId))
            return isDefaultGroup(superGroupId);

        synchronized(mainSyncLock)
        { return hasGroup(assignableGroups.get(groupId), superGroupId, false); }
    }

    @Override
    public Collection<String> getGroupNames()
    { synchronized(mainSyncLock) { return new HashSet<>(assignableGroups.keySet()); } }

    @Override
    public Collection<ID> getUsers()
    { synchronized(mainSyncLock) { return new HashSet<>(permissionsForUsers.keySet()); } }

    @Override
    public List<String> getUserPermissions(ID userId)
    {
        synchronized(mainSyncLock)
        { return getPermissions(permissionsForUsers.getOrDefault(userId, null)); }
    }

    @Override
    public List<String> getGroupPermissions(String groupdId)
    {
        if("*".equals(groupdId))
            return getDefaultPermissions();

        synchronized(mainSyncLock)
        { return getPermissions(assignableGroups.get(groupdId)); }
    }

    @Override
    public List<String> getGroupsOfUser(ID userId)
    {
        synchronized(mainSyncLock)
        { return getGroupsOf(permissionsForUsers.getOrDefault(userId, null)); }
    }

    @Override
    public List<String> getGroupsOfGroup(String groupId)
    {
        if("*".equals(groupId))
            return getDefaultGroups();

        synchronized(mainSyncLock)
        { return getGroupsOf(assignableGroups.get(groupId)); }
    }



    @Override
    public Permission assignUserPermission(ID userId, String permission)
    {
        synchronized(mainSyncLock)
        { return assignPermission(getUserPermissionsGroupOrNew(userId), permission); }
    }

    @Override
    public Permission assignGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return assignDefaultPermission(permission);
        else
            synchronized(mainSyncLock)
            { return assignPermission(getGroupPermissionsGroupOrNew(groupId), permission); }
    }

    @Override
    public Permission revokeUserPermission(ID userId, String permission)
    {
        synchronized(mainSyncLock)
        { return revokePermission(permissionsForUsers.get(userId), permission); }
    }

    @Override
    public Permission revokeGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return revokeDefaultPermission(permission);

        synchronized(mainSyncLock)
        { return revokePermission(assignableGroups.get(groupId), permission); }
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        synchronized(mainSyncLock)
        {
            PermissionGroup userPermGroup = getUserPermissionsGroupOrNew(userId);
            PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(groupIdBeingAssigned);
            markAsModified();
            userPermGroup.addPermissionGroup(permGroupBeingAssigned);
        }
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        if("*".equals(groupId))
            assignDefaultGroup(groupIdBeingAssigned);

        synchronized(mainSyncLock)
        {
            PermissionGroup permGroup = getGroupPermissionsGroupOrNew(groupId);
            PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(groupIdBeingAssigned);
            assertNotCircular(permGroup, permGroupBeingAssigned);
            markAsModified();
            permGroup.addPermissionGroup(permGroupBeingAssigned);
        }
    }

    @Override
    public void assignDefaultGroup(String groupIdBeingAssigned)
    {
        synchronized(mainSyncLock)
        {
            PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(groupIdBeingAssigned);
            assertNotCircular(defaultPermissions, permGroupBeingAssigned);
            markAsModified();
            defaultPermissions.addPermissionGroup(permGroupBeingAssigned);
        }
    }

    @Override
    protected void assignGroupTo(PermissionGroup permGroup, String groupIdBeingAssigned, boolean checkForCircular)
    { throw new UnsupportedOperationException("Variants implemented separately."); }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        synchronized(mainSyncLock)
        { return revokeGroupFrom(permissionsForUsers.get(userId), groupIdBeingRevoked); }
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        if("*".equals(groupId))
            return revokeDefaultGroup(groupIdBeingRevoked);

        synchronized(mainSyncLock)
        { return revokeGroupFrom(assignableGroups.get(groupId), groupIdBeingRevoked); }
    }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    { return revokeGroupFrom(defaultPermissions, groupIdBeingRevoked); }

    @Override
    protected boolean revokeGroupFrom(PermissionGroup permGroup, String groupIdBeingRevoked)
    {
        if(permGroup == null)
            return false;

        synchronized(mainSyncLock)
        {
            PermissionGroup permGroupBeingRevoked = assignableGroups.get(groupIdBeingRevoked);

            if(permGroupBeingRevoked == null)
                return false;

            markAsModified();
            return permGroup.removePermissionGroup(permGroupBeingRevoked);
        }
    }

    @Override
    public void clear()
    {
        synchronized(mainSyncLock)
        {
            permissionsForUsers.clear();
            assignableGroups.clear();
            defaultPermissions.clear();
        }
    }

    @Override
    public String usersToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        {
            synchronized(mainSyncLock)
            { saveUsers(writer); }
        }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    @Override
    public String groupsToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        {
            synchronized(mainSyncLock)
            { saveGroups(writer); }
        }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    @Override
    public void save() throws IOException
    {
        synchronized(mainSyncLock)
        {
            saveUsers();
            saveGroups();
            hasBeenDifferentiatedFromFiles = false;
        }
    }

    @Override
    public void load() throws IOException
    {
        synchronized(mainSyncLock)
        {
            permissionsForUsers.clear();
            assignableGroups.clear();
            defaultPermissions.clear();
            loadGroups();
            loadUsers();
            hasBeenDifferentiatedFromFiles = false;
        }
    }
}
