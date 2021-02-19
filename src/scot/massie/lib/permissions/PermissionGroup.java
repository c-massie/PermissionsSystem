package scot.massie.lib.permissions;

import java.text.ParseException;
import java.util.*;

public class PermissionGroup
{
    public PermissionGroup(String name)
    { this(name, emptyDefaultPermissions, 0L); }

    public PermissionGroup(String name, long priority)
    { this(name, emptyDefaultPermissions, priority); }

    public PermissionGroup(String name, double priority)
    { this(name, emptyDefaultPermissions, priority); }

    public PermissionGroup(String name, PermissionGroup defaultPermissions)
    { this(name, defaultPermissions, 0L); }

    public PermissionGroup(String name, PermissionGroup defaultPermissions, long priority)
    {
        this.name = name;
        this.defaultPermissions = defaultPermissions;
        this.priority = priority;
        this.priorityAsLong = priority;
        this.priorityIsLong = true;
    }

    public PermissionGroup(String name, PermissionGroup defaultPermissions, double priority)
    {
        this.name = name;
        this.defaultPermissions = defaultPermissions;
        this.priority = priority;
        this.priorityAsLong = ((Double)priority).longValue();
        this.priorityIsLong = false;
    }

    public static final Comparator<PermissionGroup> priorityComparatorHighestFirst = (a, b) ->
    {
        int result = a.priorityIsLong ? (-Long  .compare(a.priorityAsLong, b.priorityAsLong))
                                      : (-Double.compare(a.priority,       b.priority      ));

        if(result != 0)
            return result;

        return a.name.compareTo(b.name);
    };

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

    String name;
    double priority;
    long priorityAsLong;
    boolean priorityIsLong;

    PermissionSet permissionSet = new PermissionSet();
    List<PermissionGroup> referencedGroups = new ArrayList<>();
    PermissionGroup defaultPermissions;

    public String getName()
    { return name; }

    public double getPriority()
    { return priority; }

    public long getPriorityAsLong()
    { return priorityAsLong; }

    public String getPriorityAsString()
    { return priorityIsLong ? Long.toString(priorityAsLong) : Double.toString(priority); }

    public void reassignPriority(long newPriority)
    {
        priority = newPriority;
        priorityAsLong = newPriority;
        priorityIsLong = true;
    }

    public void reassignPriority(double newPriority)
    {
        this.priority = newPriority;
        this.priorityAsLong = ((Double)newPriority).longValue();
        this.priorityIsLong = false;
    }

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

    public void addPermission(String permissionAsString) throws ParseException
    { permissionSet.set(permissionAsString); }

    public void addPermissionWhileDeIndenting(String permissionAsString) throws ParseException
    { permissionSet.setWhileDeIndenting(permissionAsString); }

    public boolean removePermission(String permissionPath)
    { return permissionSet.remove(permissionPath); }

    public void addPermissionGroup(PermissionGroup permGroup)
    {
        int index = Collections.binarySearch(referencedGroups, permGroup, priorityComparatorHighestFirst);

        if(index >= 0)
            return;

        index = (index + 1) * -1;
        referencedGroups.add(index, permGroup);
    }

    public void sortPermissionGroups()
    { referencedGroups.sort(priorityComparatorHighestFirst); }

    public boolean removePermissionGroup(PermissionGroup permissionGroup)
    { return referencedGroups.remove(permissionGroup); }

    public boolean hasPermission(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().permits();
    }

    public boolean negatesPermission(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().negates();
    }

    public boolean hasGroup(String groupId)
    {
        for(PermissionGroup pg : referencedGroups)
            if(pg.name.equals(groupId) || pg.hasGroup(groupId))
                return true;

        if(defaultPermissions.name.equals(groupId) || defaultPermissions.hasGroup(groupId))
            return true;

        return false;
    }

    public boolean hasGroupDirectly(String groupId)
    {
        for(PermissionGroup pg : referencedGroups)
            if(pg.name.equals(groupId))
                return true;

        return false;
    }

    boolean containsOnlyAGroup()
    { return (permissionSet.isEmpty()) && (referencedGroups.size() == 1); }

    public boolean isEmpty()
    { return permissionSet.isEmpty() && referencedGroups.isEmpty(); }

    public void clear()
    {
        permissionSet.clear();
        referencedGroups.clear();
    }

    public String getPermissionArg(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return null;

        return mrp.getPermission().getArg();
    }

    public List<PermissionGroup> getPermissionGroups()
    { return new ArrayList<>(referencedGroups); }

    public List<String> getPermissionsAsStrings(boolean includeArgs)
    { return permissionSet.getPermissionsAsStrings(includeArgs); }

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
}
