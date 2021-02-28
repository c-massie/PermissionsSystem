package scot.massie.lib.permissions;

import java.text.ParseException;
import java.util.*;

/**
 * A collection of permissions (see {@link PermissionSet}) that may also reference other Permission groups, querying
 * them to check for the coverage of a given permission when not covered by this group directly.
 */
public class PermissionGroup
{
    /*
        To do:

        Add a list of callbacks to call when the priority of this permission group is changed.

        When a permission group adds a referenced permission group, it should add a callback to call its own
        .sortPermissionGroups() method when the priority is changed.

        When a permission group removes a referenced permission group, it should remove its callback from the now
        removed referenced permission group.

        These callbacks should not be considered when checked for emptiness.

        When I do this, I should make .sortPermissionGroups() not part of the public API. Registering these callbacks
        should also not be part of the public API.

        Ensuring that the internal order of referenced permission groups is sorted should be an implementation detail.
     */

    private static final class PriorityChangeCallback
    {
        public PriorityChangeCallback(PermissionGroup source)
        { this.source = source; }

        private final PermissionGroup source;

        public void onPriorityChange() { source.sortPermissionGroups(); }
    }

    //region initialisation

    /**
     * Creates a new permission group.
     *
     * When no priority is provided, it is 0 by default.
     * @param name The name of the permission group. This may be used as a unique identifier.
     */
    public PermissionGroup(String name)
    { this(name, emptyDefaultPermissions, 0L); }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, long priority)
    { this(name, emptyDefaultPermissions, priority); }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, double priority)
    { this(name, emptyDefaultPermissions, priority); }

    /**
     * Creates a new permission group.
     *
     * When no priority is provided, it is 0 by default.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param defaultPermissions The permission group to check if this one or any referenced by it do not cover a given
     *                           permission.
     */
    public PermissionGroup(String name, PermissionGroup defaultPermissions)
    { this(name, defaultPermissions, 0L); }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param defaultPermissions The permission group to check if this one or any referenced by it do not cover a given
     *                           permission.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, PermissionGroup defaultPermissions, long priority)
    {
        this.name = name;
        this.defaultPermissions = defaultPermissions;
        this.priority = priority;
        this.priorityAsLong = priority;
        this.priorityIsLong = true;
    }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param defaultPermissions The permission group to check if this one or any referenced by it do not cover a given
     *                           permission.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, PermissionGroup defaultPermissions, double priority)
    {
        this.name = name;
        this.defaultPermissions = defaultPermissions;
        this.priority = priority;
        this.priorityAsLong = ((Double)priority).longValue();
        this.priorityIsLong = false;
    }
    //endregion

    //region public static final fields

    /**
     * Comparator that sorts permission groups in order of priority, in order from highest to lowest.
     *
     * Where two permission groups share the same priority, order is indeterminate.
     */
    public static final Comparator<PermissionGroup> priorityComparatorHighestFirst = (a, b) ->
    {
        int result = a.priorityIsLong ? (-Long  .compare(a.priorityAsLong, b.priorityAsLong))
                                      : (-Double.compare(a.priority,       b.priority      ));

        if(result != 0)
            return result;

        return a.name.compareTo(b.name);
    };

    /**
     * A permission group to be provided as a default permission group for other permission groups.
     *
     * May not have a priority, contain any permissions, or reference any other permission groups, and never has nor
     * negates any permissions.
     */
    public static final PermissionGroup emptyDefaultPermissions = new PermissionGroup("*", null)
    {
        final String cannotMutateErrorMsg = "Cannot mutate the empty default permission group.";

        @Override
        public void reassignPriority(long newPriority)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public void reassignPriority(double newPriority)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public void addPermission(String permissionAsString)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public void addPermissionWhileDeIndenting(String permissionAsString)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public boolean removePermission(String permissionPath)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public void addPermissionGroup(PermissionGroup permGroup)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public boolean removePermissionGroup(PermissionGroup permissionGroup)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public boolean hasPermission(String permissionPath)
        { return false; }

        @Override
        public boolean negatesPermission(String permissionPath)
        { return false; }

        @Override
        public String getPermissionArg(String permissionPath)
        { return null; }

        @Override
        public boolean hasGroupDirectly(String groupId)
        { return false; }

        @Override
        public boolean hasGroup(String groupId)
        { return false; }

        @Override
        protected PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
        { return null; }
    };
    //endregion

    //region instance fields
    /**
     * The name, possibly used as a unique identifier, of the permission group.
     */
    protected String name;

    /**
     * The priority of this permission group, as a double.
     *
     * Priority determines the ordering of this group in the groups referenced by other groups, where higher priority
     * groups are queried before lower priority groups.
     */
    protected double priority;

    /**
     * The priority of this permission group, as a long.
     *
     * Priority determines the ordering of this group in the groups referenced by other groups, where higher priority
     * groups are queried before lower priority groups.
     */
    protected long priorityAsLong;

    /**
     * Whether or not this permission group's priority was provided as, and should be read as, a long. If false, it
     * should be read as a double instead.
     */
    protected boolean priorityIsLong;

    /**
     * The store of permissions for this group. Queries of the permission group's permission are directed to this.
     */
    protected final PermissionSet permissionSet = new PermissionSet();

    /**
     * Groups that should be referenced by this group.
     *
     * When this group is queried, permissions queries are checked against the stored permission set. If the permission
     * set doesn't cover the permission, (allowing *or* negating) the query is run against the referenced groups until
     * one is found that *does* cover the specified permission. These groups are checked in order from higher priority
     * to lower priority.
     */
    protected final List<PermissionGroup> referencedGroups = new ArrayList<>();

    /**
     * The permission group to check if this one and all others referenced do not cover a given permission.
     *
     * Queries defer to this only after this group's permission set and all other referenced groups have been queried,
     * and only if none of them have permissions covering the specified one.
     */
    protected PermissionGroup defaultPermissions;

    /**
     * Callback that alerts this permission group when the priority of a permission group this group references changes
     * its priority, which may require re-sorting the list of referenced groups.
     */
    private final PriorityChangeCallback priorityChangeCallback = new PriorityChangeCallback(this);

    /**
     * The callbacks to call when this permission group's priority is changed. These should be the callbacks provided
     * by all permission groups that reference this one.
     */
    private final Collection<PriorityChangeCallback> callbacksToCallOnPriorityChange = new HashSet<>();
    //endregion

    //region methods
    //region accessors
    //region getters

    /**
     * Gets this name of this permission group. This may be used as a unique identifier.
     * @return The name of this permission group.
     */
    public String getName()
    { return name; }

    /**
     * Gets the priority of this permission group, as a double.
     *
     * The priority of a permission group defines its place in the order of permission groups referenced by other
     * permission groups, where a check for the allowance of a given permission, should the group not cover it, defers
     * to its referenced permission groups of higher priority before lower priority.
     * @return This permission group's priority as a double.
     */
    public double getPriority()
    { return priority; }

    /**
     * Gets the priority of this permission group, as a long.
     *
     * The priority of a permission group defines its place in the order of permission groups referenced by other
     * permission groups, where a check for the allowance of a given permission, should the group not cover it, defers
     * to its referenced permission groups of higher priority before lower priority.
     * @return This permission group's priority as a long. Where this permission group's priority is given as a double,
     *         this returns the priority truncated to a long, as given by Double.longValue().
     */
    public long getPriorityAsLong()
    { return priorityAsLong; }

    /**
     * Gets a string representation of this permission group's priority. See {@link #getPriority()}.
     * @return A string repesentation of this permission group's priority. Where the priority is given as a double, this
     *         may include decimal places.
     */
    public String getPriorityAsString()
    { return priorityIsLong ? Long.toString(priorityAsLong) : Double.toString(priority); }

    /**
     * Gets the {@link Permission} object contained within permission group's {@link PermissionSet} corresponding to
     * the given permission.
     *
     * Where this group's permission set contains no such permission, checks for this permission iteratively in each
     * permission group referenced by this permission, starting with highest priority and going to lowest.
     *
     * Where this group's permission set and referenced permission groups contain no such permission, checks for this
     * permission in the default permission group.
     *
     * Where the given permission is not covered by this permission group's permission set, any referenced permission
     * group, or the default permission group, returns null, to indicate that there is no permission relevant to the
     * given permission.
     * @param permissionAsString The permission as a string to get the most relevant permission to.
     * @return The most relevant permission found among this permission group's permission set, the referenced
     *         permission groups, or the default group. If no relevant permission is found, returns null.
     */
    protected PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
    {
        PermissionSet.PermissionWithPath mrp = permissionSet.getMostRelevantPermission(permissionAsString);

        if(mrp != null)
            return mrp;

        for(PermissionGroup permGroup : referencedGroups)
        {
            mrp = permGroup.getMostRelevantPermission(permissionAsString);

            if(mrp != null)
                return mrp;
        }

        // Not an infinite recursive loop; eventually stops at a emptyDefaultPermissions where this method returns null.
        return defaultPermissions.getMostRelevantPermission(permissionAsString);
    }

    /**
     * Gets the permission argument of the permission covering the given permission.
     *
     * The permission argument is given in the save string after the permission path, after all other suffixed, prefixed
     * with a colon. (':')
     *
     * Where the given permission is not covered by any permission of this permission group's {@link PermissionSet}, any
     * referenced permission group, or the given default permission group, or where the permission covering it does not
     * have a permission argument provided, returns null instead.
     *
     * A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.
     *
     * This permission group is considered to cover a given permission for the purposes of this, where this permission
     * group's permission set, any of the referenced permission groups, or the given default permission group, contains
     * any permissions covering it, as defined above.
     * @param permissionPath The permission to get the permission argument of.
     * @return The permission argument of the most relevant permission to the given one. Where there is no relevant
     *         permission, or where that permission does not have a string arg, returns null instead.
     */
    public String getPermissionArg(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return null;

        return mrp.getPermission().getArg();
    }

    /**
     * Gets the permission groups referenced by this permission.
     * @return A list of the permission groups referenced by this permission, in order from highest priority to lowest.
     */
    public List<PermissionGroup> getPermissionGroups()
    { return new ArrayList<>(referencedGroups); }

    /**
     * Gets string representations of all permissions covered directly by this permission group.
     *
     * This ignored permissions in referenced permission groups or the default permission group.
     *
     * See {@link PermissionSet#getPermissionsAsStrings(boolean)}.
     * @param includeArgs Whether or not to include the permission arguments in the string representations.
     * @return A list of string representations of the directly included permissions in this permission group, ordered
     *         by the alphabetical order of the nodes.
     */
    public List<String> getPermissionsAsStrings(boolean includeArgs)
    { return permissionSet.getPermissionsAsStrings(includeArgs); }
    //endregion
    //region state

    /**
     * Checks whether this group has the given permission.
     *
     * A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.
     *
     * This permission group is considered to cover a given permission for the purposes of this, where this permission
     * group's permission set, any of the referenced permission groups, or the given default permission group, contains
     * any permissions covering it, as defined above.
     * @param permissionPath The permission path to check for the coverage and allowance of.
     * @return True if the given permission path is allowed by this permission group. Otherwise, false.
     */
    public boolean hasPermission(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().permits();
    }

    /**
     * Checks whether this group specifically negates the given permission.
     *
     * A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.
     *
     * This permission group is considered to cover a given permission for the purposes of this, where this permission
     * group's permission set, any of the referenced permission groups, or the given default permission group, contains
     * any permissions covering it, as defined above.
     * @param permissionPath The permission path to check for the coverage and negation of.
     * @return True if the given permission path is specifically negated (and not simply not covered by) this permission
     *         group. Otherwise, false.
     */
    public boolean negatesPermission(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().negates();
    }

    /**
     * Whether or not this group directly or indirectly references a group with the given name.
     *
     * This takes into account groups references by groups references by this one, and so on.
     * @param groupId The name of the group to check to see if this references.
     * @return True if this group or any group referenced by this group directly or indirectly references a group by the
     *         given name. Otherwise, false.
     */
    public boolean hasGroup(String groupId)
    {
        for(PermissionGroup pg : referencedGroups)
            if(pg.name.equals(groupId) || pg.hasGroup(groupId))
                return true;

        if(defaultPermissions.name.equals(groupId) || defaultPermissions.hasGroup(groupId))
            return true;

        return false;
    }

    /**
     * Whether or not this group directly references a group with the given name.
     *
     * This ignores the groups referenced by the groups referenced by this one.
     * @param groupId The name of the group to check to see if this references.
     * @return True if this group references a group by the given name. Otherwise, false.
     */
    public boolean hasGroupDirectly(String groupId)
    {
        for(PermissionGroup pg : referencedGroups)
            if(pg.name.equals(groupId))
                return true;

        return false;
    }

    /**
     * Gets whether or not this permission groups contains no permissions, and references only a single permissions
     * group.
     * @return True if this permission group has no permissions, and references exactly one other group. Otherwise,
     *         false.
     */
    boolean containsOnlyAGroup()
    { return (permissionSet.isEmpty()) && (referencedGroups.size() == 1); }

    /**
     * Gets whether or not this permission group contains any permissions, or references any groups. Ignores the default
     * group if provided.
     * @return True if this permission group contains no permissions and references no groups, apart from any provided
     *         default group. Otherwise, false.
     */
    public boolean isEmpty()
    { return permissionSet.isEmpty() && referencedGroups.isEmpty(); }
    //endregion

    /**
     * Gets a multi-line string representation of this permission group.
     *
     * The returned string's first line is the permission group's header, made up of the name given to the permission
     * group, and, if non-default, the priority of this group.
     *
     * This is followed by the names of each referenced group's name, one-per-line, indented four spaces.
     *
     * This is followed by the string representation of the contained {@link PermissionSet}, as given by its own
     * {@link PermissionSet#toSaveString() toSaveString method}.
     *
     * The default permission group is not represented in the save string.
     * @return A multi-lined string representation of this permission group.
     */
    public String toSaveString()
    {
        StringBuilder result = new StringBuilder((priority == 0) ? (name) : (name + ": " + getPriorityAsString()));

        if(containsOnlyAGroup())
            return result.append(" #").append(referencedGroups.get(0).getName()).toString();

        for(PermissionGroup permGroup : referencedGroups)
            result.append("\n    #").append(permGroup.getName());

        if(permissionSet.hasAny())
            result.append("\n").append(permissionSet.toSaveString().replaceAll("(?m)^(?=.+)", "    "));

        return result.toString();
    }
    //endregion
    //region mutators
    //region permissions

    /**
     * Adds a permission to this permission group.
     * @param permissionAsString The permission to add.
     * @throws ParseException If the provided permission was not parsable as a string.
     */
    public void addPermission(String permissionAsString) throws ParseException
    { permissionSet.set(permissionAsString); }

    /**
     * Adds a permission to this permission group, after having deïndented the string by 4 spaces.
     *
     * See {@link PermissionSet#setWhileDeIndenting(String)}.
     * @param permissionAsString The permission to add.
     * @throws ParseException If the provided permission was not parsable as a string.
     */
    public void addPermissionWhileDeIndenting(String permissionAsString) throws ParseException
    { permissionSet.setWhileDeIndenting(permissionAsString); }

    /**
     * Removes the given permission from the permission group.
     *
     * See {@link PermissionSet#remove(String)}.
     * @param permissionPath The permission to remove from this group.
     * @return True if this group was modified as a result of this call. Otherwise, false.
     */
    public boolean removePermission(String permissionPath)
    { return permissionSet.remove(permissionPath); }
    //endregion
    //region permission groups

    /**
     * Adds a permission group to be referenced to this group. This will allow this permission group to query the
     * given permission group for permissions that this permission does not cover itself.
     * @param permGroup The permission group to add as a referenced permission group of this one.
     */
    public void addPermissionGroup(PermissionGroup permGroup)
    {
        int index = Collections.binarySearch(referencedGroups, permGroup, priorityComparatorHighestFirst);

        if(index >= 0)
            return;

        index = (index + 1) * -1;
        referencedGroups.add(index, permGroup);
        permGroup.registerPriorityChangeCallback(priorityChangeCallback);
    }

    /**
     * Ensures that the permissions in this permission group are sorted in order from higher priority to lowest
     * priority.
     */
    protected void sortPermissionGroups()
    { referencedGroups.sort(priorityComparatorHighestFirst); }

    /**
     * Removes a permission group as a group referenced by this permission group. Disassociates it from this permission
     * group. This will mean the given permission group will no longer be able to be queried by this permission group
     * for permissions that this group itself does not have.
     * @param permissionGroup The permission group to remove as a group referenced by this one.
     * @return True if this permission group was modified as a result of this call. Otherwise, false.
     */
    public boolean removePermissionGroup(PermissionGroup permissionGroup)
    {
        if(referencedGroups.remove(permissionGroup))
        {
            permissionGroup.deregisterPriorityChangeCallback(priorityChangeCallback);
            return true;
        }
        else
            return false;
    }
    //endregion
    //region priority

    /**
     * Changes the priority of this permission group to the given priority.
     *
     * Note that you should {@link #sortPermissionGroups() sort} any permission groups referencing this one after
     * changing the priority, as this may result in this permission group being out of order in another group's
     * referenced groups.
     * @param newPriority The value to set this permission group's priority to.
     */
    public void reassignPriority(long newPriority)
    {
        priority = newPriority;
        priorityAsLong = newPriority;
        priorityIsLong = true;

        for(PriorityChangeCallback callback : callbacksToCallOnPriorityChange)
            callback.onPriorityChange();
    }

    /**
     * Changes the priority of this permission group to the given priority.
     *
     * Note that you should {@link #sortPermissionGroups() sort} any permission groups referencing this one after
     * changing the priority, as this may result in this permission group being out of order in another group's
     * referenced groups.
     * @param newPriority The value to set this permission group's priority to.
     */
    public void reassignPriority(double newPriority)
    {
        this.priority = newPriority;
        this.priorityAsLong = ((Double)newPriority).longValue();
        this.priorityIsLong = false;

        for(PriorityChangeCallback callback : callbacksToCallOnPriorityChange)
            callback.onPriorityChange();
    }

    /**
     * Adds a callback to call when this permission group's priority changes.
     * @param callback The callback to call
     */
    private void registerPriorityChangeCallback(PriorityChangeCallback callback)
    { callbacksToCallOnPriorityChange.add(callback); }

    /**
     * Removes a callback to call when this permission group's priority changes, it will no longer be called.
     * @param callback The callback to no longer call.
     */
    private void deregisterPriorityChangeCallback(PriorityChangeCallback callback)
    { callbacksToCallOnPriorityChange.remove(callback); }
    //endregion

    /**
     * Removes all permissions and referenced groups from this permission group. Does not affect the default group.
     */
    public void clear()
    {
        permissionSet.clear();
        referencedGroups.clear();
    }
    //endregion
    //endregion
}
