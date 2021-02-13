package scot.massie.lib.permissions;

import java.text.ParseException;
import java.util.*;

public class PermissionGroup
{
    public PermissionGroup(String name)
    { this(name, 0L); }

    public PermissionGroup(String name, long priority)
    {
        this.name = name;
        this.priority = priority;
        this.priorityAsLong = priority;
        this.priorityIsLong = true;
    }

    public PermissionGroup(String name, double priority)
    {
        this.name = name;
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

    String name;
    double priority;
    long priorityAsLong;
    boolean priorityIsLong;

    PermissionSet permissionSet = new PermissionSet();
    List<PermissionGroup> referencedGroups = new ArrayList<>();

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

    private PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
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

        return null;
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

    public String getPermissionArg(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return null;

        return mrp.getPermission().getArg();
    }

    public List<PermissionGroup> getPermissionGroups()
    { return new ArrayList<>(referencedGroups); }

    public String toSaveString()
    {
        StringBuilder result = new StringBuilder((priority == 0) ? (name) : (name + ": " + getPriorityAsString()));

        for(PermissionGroup permGroup : referencedGroups)
            result.append("\n    #").append(permGroup.getName());

        if(permissionSet.hasAny())
            result.append("\n").append(permissionSet.toSaveString().replaceAll("(?m)^(?=.+)", "    "));

        return result.toString();
    }
}
