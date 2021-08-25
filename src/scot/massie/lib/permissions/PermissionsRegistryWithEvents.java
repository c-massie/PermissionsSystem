package scot.massie.lib.permissions;

import scot.massie.lib.events.Event;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.ProtectedEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.events.args.EventArgs;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Function;

/**
 * <p>A {@link PermissionsRegistry permissions registry} with events for when the contents of the registry change.</p>
 *
 * @see scot.massie.lib.permissions.PermissionsRegistry
 * @param <ID>The type of the unique identifier used to represent users.
 */
public class PermissionsRegistryWithEvents<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    /**
     * Event args for when the contents of the permissions registry change.
     */
    public static class ContentsChangedEventArgs implements EventArgs
    {

    }

    /**
     * Fired when the contents of the permissions registry are changed.
     */
    protected final InvokableEvent<ContentsChangedEventArgs> contentsChanged_internal = new SetEvent<>();

    /**
     * Fired when the contents of the permissions registry are changed.
     */
    public final Event<ContentsChangedEventArgs> contentsChanged = new ProtectedEvent<>(contentsChanged_internal);

    /**
     * Creates a new permissions registry with the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     * @param usersFile The filepath of the users permissions save file.
     * @param groupsFile The filepath of the groups permissions save file.
     */
    public PermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString,
                                         Path usersFile,
                                         Path groupsFile)
    { super(idToString, idFromString, usersFile, groupsFile); }

    /**
     * Creates a new permissions registry without the ability to save and load to and from files.
     * @param idToString The conversion for turning a user ID into a reversible string representation of it.
     * @param idFromString The conversion for turning a user ID as a string string back into a user ID object.
     */
    public PermissionsRegistryWithEvents(Function<ID, String> idToString, Function<String, ID> idFromString)
    { super(idToString, idFromString); }

    @Override
    public void assignUserPermission(ID userId, String permission)
    {
        super.assignUserPermission(userId, permission);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public void assignGroupPermission(String groupId, String permission)
    {
        super.assignGroupPermission(groupId, permission);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public void assignDefaultPermission(String permission)
    {
        super.assignDefaultPermission(permission);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public boolean revokeUserPermission(ID userId, String permission)
    {
        boolean result = super.revokeUserPermission(userId, permission);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
        return result;
    }

    @Override
    public boolean revokeGroupPermission(String groupId, String permission)
    {
        boolean result = super.revokeGroupPermission(groupId, permission);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
        return result;
    }

    @Override
    public boolean revokeDefaultPermission(String permission)
    {
        boolean result = super.revokeDefaultPermission(permission);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
        return result;
    }

    @Override
    public void assignGroupToUser(ID userId, String groupIdBeingAssigned)
    {
        super.assignGroupToUser(userId, groupIdBeingAssigned);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public void assignGroupToGroup(String groupId, String groupIdBeingAssigned)
    {
        super.assignGroupToGroup(groupId, groupIdBeingAssigned);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public void assignDefaultGroup(String groupIdBeingAssigned)
    {
        super.assignDefaultGroup(groupIdBeingAssigned);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public boolean revokeGroupFromUser(ID userId, String groupIdBeingRevoked)
    {
        boolean result = super.revokeGroupFromUser(userId, groupIdBeingRevoked);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
        return result;
    }

    @Override
    public boolean revokeGroupFromGroup(String groupId, String groupIdBeingRevoked)
    {
        boolean result = super.revokeGroupFromGroup(groupId, groupIdBeingRevoked);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
        return result;
    }

    @Override
    public boolean revokeDefaultGroup(String groupIdBeingRevoked)
    {
        boolean result = super.revokeDefaultGroup(groupIdBeingRevoked);
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
        return result;
    }

    @Override
    public void clear()
    {
        super.clear();
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }

    @Override
    public void load() throws IOException
    {
        super.load();
        contentsChanged_internal.invoke(new ContentsChangedEventArgs());
    }
}
