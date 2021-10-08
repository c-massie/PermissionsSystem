package scot.massie.lib.permissions;

import scot.massie.lib.permissions.exceptions.GroupMissingPermissionException;
import scot.massie.lib.permissions.exceptions.PermissionNotDefaultException;
import scot.massie.lib.permissions.exceptions.UserMissingPermissionException;
import scot.massie.lib.utils.wrappers.MutableWrapper;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
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
    { super(new ThreadsafePermissionGroup("*"), idToString, idFromString, usersFile, groupsFile); }

    public ThreadsafePermissionsRegistry(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(new ThreadsafePermissionGroup("*"), idToString, idFromString); }
    

    @Override
    public PermissionStatus getUserPermissionStatus(ID userId, String permission)
    {
        synchronized(permissionsForUsers)
        { return getPermissionStatus(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public PermissionStatus getGroupPermissionStatus(String groupId, String permission)
    {
        synchronized(assignableGroups)
        { return getPermissionStatus(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public boolean userHasPermission(ID userId, String permission)
    {
        synchronized(permissionsForUsers)
        { return hasPermission(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public boolean groupHasPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return isDefaultPermission(permission);

        synchronized(assignableGroups)
        { return hasPermission(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public boolean userHasAnySubPermissionOf(ID userId, String permission)
    {
        synchronized(permissionsForUsers)
        { return hasAnySubPermissionOf(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public boolean groupHasAnySubPermissionOf(String groupId, String permission)
    {
        if("*".equals(groupId))
            return isOrAnySubPermissionOfIsDefault(permission);

        synchronized(assignableGroups)
        { return hasAnySubPermissionOf(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public String getUserPermissionArg(ID userId, String permission)
    {
        synchronized(permissionsForUsers)
        { return getPermissionArg(permissionsForUsers.get(userId), permission, true); }
    }

    @Override
    public String getGroupPermissionArg(String groupId, String permission)
    {
        if("*".equals(groupId))
            return getDefaultPermissionArg(permission);

        synchronized(assignableGroups)
        { return getPermissionArg(assignableGroups.get(groupId), permission, false); }
    }

    @Override
    public boolean userHasGroup(ID userId, String groupId)
    {
        synchronized(permissionsForUsers)
        { return hasGroup(permissionsForUsers.get(userId), groupId, true); }
    }

    @Override
    public boolean groupExtendsFromGroup(String groupId, String superGroupId)
    {
        if("*".equals(groupId))
            return isDefaultGroup(superGroupId);

        synchronized(assignableGroups)
        { return hasGroup(assignableGroups.get(groupId), superGroupId, false); }
    }

    @Override
    public Collection<String> getGroupNames()
    { synchronized(assignableGroups) { return new HashSet<>(assignableGroups.keySet()); } }

    @Override
    public Collection<ID> getUsers()
    { synchronized(assignableGroups) { return new HashSet<>(permissionsForUsers.keySet()); } }

    @Override
    public List<String> getUserPermissions(ID userId)
    {
        synchronized(permissionsForUsers)
        { return getPermissions(permissionsForUsers.getOrDefault(userId, null)); }
    }

    @Override
    public List<String> getGroupPermissions(String groupdId)
    {
        if("*".equals(groupdId))
            return getDefaultPermissions();

        synchronized(assignableGroups)
        { return getPermissions(assignableGroups.get(groupdId)); }
    }

    @Override
    public List<String> getGroupsOfUser(ID userId)
    {
        synchronized(permissionsForUsers)
        { return getGroupsOf(permissionsForUsers.getOrDefault(userId, null)); }
    }

    @Override
    public List<String> getGroupsOfGroup(String groupId)
    {
        if("*".equals(groupId))
            return getDefaultGroups();

        synchronized(assignableGroups)
        { return getGroupsOf(assignableGroups.get(groupId)); }
    }



    @Override
    public void assignUserPermission(ID userId, String permission)
    {
        synchronized(permissionsForUsers)
        { assignPermission(getUserPermissionsGroupOrNew(userId), permission); }
    }

    @Override
    public void assignGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            assignDefaultPermission(permission);
        else
            synchronized(assignableGroups)
            { assignPermission(getGroupPermissionsGroupOrNew(groupId), permission); }
    }

    @Override
    public boolean revokeUserPermission(ID userId, String permission)
    {
        synchronized(permissionsForUsers)
        { return revokePermission(permissionsForUsers.get(userId), permission); }
    }

    @Override
    public boolean revokeGroupPermission(String groupId, String permission)
    {
        if("*".equals(groupId))
            return revokeDefaultPermission(permission);

        synchronized(assignableGroups)
        { return revokePermission(assignableGroups.get(groupId), permission); }
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        synchronized(permissionsForUsers)
        {
            synchronized(assignableGroups)
            {
                PermissionGroup userPermGroup = getUserPermissionsGroupOrNew(userId);
                PermissionGroup permGroupBeingAssigned = getGroupPermissionsGroupOrNew(groupIdBeingAssigned);
                markAsModified();
                userPermGroup.addPermissionGroup(permGroupBeingAssigned);
            }
        }
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        if("*".equals(groupId))
            assignDefaultGroup(groupIdBeingAssigned);

        synchronized(assignableGroups)
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
        synchronized(assignableGroups)
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
        synchronized(permissionsForUsers)
        { return revokeGroupFrom(permissionsForUsers.get(userId), groupIdBeingRevoked); }
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        if("*".equals(groupId))
            return revokeDefaultGroup(groupIdBeingRevoked);

        synchronized(assignableGroups)
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

        synchronized(assignableGroups)
        {
            if(permGroup == defaultPermissions)
            {
                MutableWrapper<Boolean> result = new MutableWrapper<>(false);

                ((ThreadsafePermissionGroup)defaultPermissions).doAtomically(() ->
                {
                    PermissionGroup permGroupBeingRevoked = assignableGroups.get(groupIdBeingRevoked);

                    if(permGroupBeingRevoked == null)
                        return;

                    markAsModified();
                    result.set(permGroup.removePermissionGroup(permGroupBeingRevoked));
                });

                return result.get();
            }
            else
            {
                PermissionGroup permGroupBeingRevoked = assignableGroups.get(groupIdBeingRevoked);

                if(permGroupBeingRevoked == null)
                    return false;

                markAsModified();
                return permGroup.removePermissionGroup(permGroupBeingRevoked);
            }
        }
    }

    @Override
    public void clear()
    {
        synchronized(permissionsForUsers)
        {
            synchronized(assignableGroups)
            {
                ((ThreadsafePermissionGroup)defaultPermissions).doAtomically(() ->
                {
                    permissionsForUsers.clear();
                    assignableGroups.clear();
                    defaultPermissions.clear();
                });
            }
        }
    }



    @Override
    public String usersToSaveString()
    {
        StringWriter sw = new StringWriter();

        try(BufferedWriter writer = new BufferedWriter(sw))
        {
            synchronized(permissionsForUsers)
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
            synchronized(assignableGroups)
            { saveGroups(writer); }
        }
        catch(IOException e)
        { e.printStackTrace(); }

        return sw.toString();
    }

    @Override
    public void save() throws IOException
    {
        synchronized(permissionsForUsers)
        {
            synchronized(assignableGroups)
            {
                MutableWrapper<IOException> toRethrow = new MutableWrapper<>(null);

                ((ThreadsafePermissionGroup)defaultPermissions).doAtomically(() ->
                {
                    try
                    {
                        saveUsers();
                        saveGroups();
                        hasBeenDifferentiatedFromFiles = false;
                    }
                    catch(IOException ex)
                    { toRethrow.set(ex); }
                });

                if(toRethrow.get() != null)
                    throw new IOException(toRethrow.get());
            }
        }
    }

    @Override
    public void load() throws IOException
    {
        synchronized(permissionsForUsers)
        {
            synchronized(assignableGroups)
            {
                MutableWrapper<IOException> toRethrow = new MutableWrapper<>(null);

                ((ThreadsafePermissionGroup)defaultPermissions).doAtomically(() ->
                {
                    try
                    {
                        permissionsForUsers.clear();
                        assignableGroups.clear();
                        defaultPermissions.clear();
                        loadGroups();
                        loadUsers();
                        hasBeenDifferentiatedFromFiles = false;
                    }
                    catch(IOException ex)
                    { toRethrow.set(ex); }
                });

                if(toRethrow.get() != null)
                    throw new IOException(toRethrow.get());
            }
        }
    }
}
