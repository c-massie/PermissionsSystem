package scot.massie.lib.permissions;

import scot.massie.lib.functionalinterfaces.Procedure;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

/**
 * A thread-safe variant of {@link PermissionGroup}.
 *
 * A synchronized lock of one permission group may be entered while already in the lock of another permission group
 * which references it, (that is; of a permission group which "has" the former group) but as circular dependencies
 * aren't allowed, there shoudn't be two permission groups mutually waiting for the other to exit their locks, and
 * deadlocks should be prevented.
 *
 * An optimisation of PermissionGroup is that referenced PermissionGroups are ordered ahead of time, either when they're
 * added/removed, or when the priority of one of those referenced PermissionGroups changes. This isn't supported in
 * ThreadsafePermissionGroup.
 */
public class ThreadsafePermissionGroup extends PermissionGroup
{
    /**
     * The main synchronisation lock.
     */
    protected static final Object mainSyncLock = new Object();

    /**
     * Creates a new threadsafe permission group object.
     * @param name The name of the permission group.
     */
    public ThreadsafePermissionGroup(String name)
    { super(name); }

    /**
     * Creates a new threadsafe permission group object.
     * @param name The name of the permission group.
     * @param priority The priority of the permission group. Permission groups fall back on their referenced permission
     *                 groups in order of priority, checking the highest priority first.
     */
    public ThreadsafePermissionGroup(String name, long priority)
    { super(name, priority); }

    /**
     * Creates a new threadsafe permission group object.
     * @param name The name of the permission group.
     * @param priority The priority of the permission group. Permission groups fall back on their referenced permission
     *                 groups in order of priority, checking the highest priority first.
     */
    public ThreadsafePermissionGroup(String name, double priority)
    { super(name, priority); }

    /**
     * Creates a new threadsafe permission group object.
     * @param name The name of the permission group.
     * @param defaultPermissions The permission group that should be fallen back on after checking all referenced
     *                           permission groups.
     */
    public ThreadsafePermissionGroup(String name, PermissionGroup defaultPermissions)
    { super(name, defaultPermissions); }

    /**
     * Creates a new threadsafe permission group object.
     * @param name The name of the permission group.
     * @param defaultPermissions The permission group that should be fallen back on after checking all referenced
     *                           permission groups.
     * @param priority The priority of the permission group. Permission groups fall back on their referenced permission
     *                 groups in order of priority, checking the highest priority first.
     */
    public ThreadsafePermissionGroup(String name, PermissionGroup defaultPermissions, long priority)
    { super(name, defaultPermissions, priority); }

    /**
     * Creates a new threadsafe permission group object.
     * @param name The name of the permission group.
     * @param defaultPermissions The permission group that should be fallen back on after checking all referenced
     *                           permission groups.
     * @param priority The priority of the permission group. Permission groups fall back on their referenced permission
     *                 groups in order of priority, checking the highest priority first.
     */
    public ThreadsafePermissionGroup(String name, PermissionGroup defaultPermissions, double priority)
    { super(name, defaultPermissions, priority); }

    /**
     * Performs an operation within this ThreadsafePermissionGroup's synchronisation lock.
     * @param thingToDo The operation to perform.
     */
    public void doAtomically(Procedure thingToDo)
    {
        synchronized(mainSyncLock)
        { thingToDo.run(); }
    }

    @Override
    public double getPriority()
    { synchronized(mainSyncLock) { return priority; } }

    @Override
    public long getPriorityAsLong()
    { synchronized(mainSyncLock) { return priorityAsLong; } }

    @Override
    public String getPriorityAsString()
    { synchronized(mainSyncLock) { return super.getPriorityAsString(); } }

    @Override
    protected PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
    {
        synchronized(mainSyncLock)
        {
            PermissionSet.PermissionWithPath mrp = permissionSet.getMostRelevantPermission(permissionAsString);

            if(mrp != null)
                return mrp;

            List<PermissionGroup> groups = new ArrayList<>(this.referencedGroups);
            groups.sort(priorityComparatorHighestFirst);

            for(PermissionGroup permGroup : groups)
            {
                mrp = permGroup.getMostRelevantPermission(permissionAsString);

                if(mrp != null)
                    return mrp;
            }

            // Not an infinite recursive loop; eventually stops at a emptyDefaultPermissions where this method returns
            // null.
            return defaultPermissions.getMostRelevantPermission(permissionAsString);
        }
    }

    @Override
    protected PermissionSet.PermissionWithPath getMostRelevantPermission(List<String> permissionAsStrings)
    {
        synchronized(mainSyncLock)
        {
            PermissionSet.PermissionWithPath mrp = permissionSet.getMostRelevantPermission(permissionAsStrings);

            if(mrp != null)
                return mrp;

            List<PermissionGroup> groups = new ArrayList<>(this.referencedGroups);
            groups.sort(priorityComparatorHighestFirst);

            for(PermissionGroup permGroup : groups)
            {
                mrp = permGroup.getMostRelevantPermission(permissionAsStrings);

                if(mrp != null)
                    return mrp;
            }

            // Not an infinite recursive loop; eventually stops at a emptyDefaultPermissions where this method returns
            // null.
            return defaultPermissions.getMostRelevantPermission(permissionAsStrings);
        }
    }

    @Override
    public List<PermissionGroup> getPermissionGroups()
    {
        synchronized(mainSyncLock)
        {
            ArrayList<PermissionGroup> result = new ArrayList<>(super.getPermissionGroups());
            result.sort(priorityComparatorHighestFirst);
            return result;
        }
    }

    @Override
    public List<String> getPermissionsAsStrings(boolean includeArgs)
    { synchronized(mainSyncLock) { return super.getPermissionsAsStrings(includeArgs); } }

    @Override
    protected boolean hasPermissionOrAnyUnder(String permissionPath, Predicate<PermissionSet.PermissionWithPath> check)
    {
        // Add check for where all permissions under the path are included because it's covered by something that covers it
        // Add optimisation where everything's negated.

        synchronized(mainSyncLock)
        {
            if(permissionSet.hasPermissionOrAnyUnderWhere(permissionPath, check))
                return true;

            if(permissionSet.negatesPermission(permissionPath))
                return false;

            Collection<PermissionGroup> pgroupsAlreadyChecked = new ArrayList<>();

            Predicate<PermissionSet.PermissionWithPath> pgroupsAlreadyCheckedCheck = pwp ->
            {
                if(!check.test(pwp))
                    return false;

                if(permissionSet.negatesPermission(pwp.getPath()))
                    return false;

                for(PermissionGroup pgroup : pgroupsAlreadyChecked)
                    if(pgroup.negatesPermission(pwp.getPath()))
                        return false;

                return true;
            };

            List<PermissionGroup> groups = new ArrayList<>(this.referencedGroups);
            groups.sort(priorityComparatorHighestFirst);

            for(PermissionGroup permGroup : groups)
            {
                if(permGroup.hasPermissionOrAnyUnder(permissionPath, pgroupsAlreadyCheckedCheck))
                    return true;

                pgroupsAlreadyChecked.add(permGroup);
            }

            if(defaultPermissions.hasPermissionOrAnyUnder(permissionPath, pgroupsAlreadyCheckedCheck))
                return true;
        }

        return false;
    }

    @Override
    public boolean hasGroup(String groupId)
    {
        synchronized(mainSyncLock)
        {
            List<PermissionGroup> groups = new ArrayList<>(this.referencedGroups);
            groups.sort(priorityComparatorHighestFirst);

            for(PermissionGroup pg : groups)
                if(pg.name.equals(groupId) || pg.hasGroup(groupId))
                    return true;

            if(defaultPermissions.name.equals(groupId) || defaultPermissions.hasGroup(groupId))
                return true;
        }

        return false;
    }

    @Override
    public boolean hasGroupDirectly(String groupId)
    {
        synchronized(mainSyncLock)
        {
            List<PermissionGroup> groups = new ArrayList<>(this.referencedGroups);
            groups.sort(priorityComparatorHighestFirst);

            for(PermissionGroup pg : groups)
                if(pg.name.equals(groupId))
                    return true;
        }

        return false;
    }

    @Override
    boolean containsOnlyAGroup()
    { synchronized(mainSyncLock) { return super.containsOnlyAGroup(); } }

    @Override
    public boolean isEmpty()
    { synchronized(mainSyncLock) { return super.isEmpty(); } }

    @Override
    public String toSaveString()
    {
        StringBuilder result = new StringBuilder((priority == 0) ? (name) : (name + ": " + getPriorityAsString()));

        List<PermissionGroup> groups = new ArrayList<>(this.referencedGroups);
        groups.sort(priorityComparatorHighestFirst);

        if(containsOnlyAGroup())
            return result.append(" #").append(groups.get(0).getName()).toString();

        for(PermissionGroup permGroup : groups)
            result.append("\n    #").append(permGroup.getName());

        if(permissionSet.hasAny())
            result.append("\n").append(permissionSet.toSaveString().replaceAll("(?m)^(?=.+)", "    "));

        return result.toString();
    }

    @Override public String toString()
    { synchronized(mainSyncLock) { return super.toString(); } }

    @Override
    public void addPermission(String permissionAsString) throws ParseException
    { synchronized(mainSyncLock) { super.addPermission(permissionAsString); } }

    @Override
    public void addPermissionWhileDeIndenting(String permissionAsString) throws ParseException
    { synchronized(mainSyncLock) { super.addPermissionWhileDeIndenting(permissionAsString); } }

    @Override
    public boolean removePermission(String permissionPath)
    { synchronized(mainSyncLock) { return super.removePermission(permissionPath); } }

    @Override
    public void addPermissionGroup(PermissionGroup permGroup)
    {
        synchronized(mainSyncLock)
        {
            if(referencedGroups.contains(permGroup))
                return;

            referencedGroups.add(permGroup);
        }
    }

    @Override
    protected void sortPermissionGroups()
    { synchronized(mainSyncLock) { super.sortPermissionGroups(); } }

    @Override
    public boolean removePermissionGroup(PermissionGroup permissionGroup)
    { synchronized(mainSyncLock) { return referencedGroups.remove(permissionGroup); } }

    @Override
    public void reassignPriority(long newPriority)
    {
        synchronized(mainSyncLock)
        {
            priority = newPriority;
            priorityAsLong = newPriority;
            priorityIsLong = true;
        }
    }

    @Override
    public void reassignPriority(double newPriority)
    {
        synchronized(mainSyncLock)
        {
            this.priority = newPriority;
            this.priorityAsLong = ((Double) newPriority).longValue();
            this.priorityIsLong = false;
        }
    }

    @Override
    protected void registerPriorityChangeCallback(PriorityChangeCallback callback)
    { throw new RuntimeException("ThreadsafePermissionGroup does not support priority change callbacks."); }

    @Override
    protected void deregisterPriorityChangeCallback(PriorityChangeCallback callback)
    { throw new RuntimeException("ThreadsafePermissionGroup does not support priority change callbacks."); }

    @Override
    public void clear()
    {
        synchronized(mainSyncLock)
        {
            permissionSet.clear();
            referencedGroups.clear();
        }
    }
}
