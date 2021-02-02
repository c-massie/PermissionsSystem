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

    public static final Comparator<PermissionGroup> priorityComparatorLowestFirst
            = (a, b) -> a.priorityIsLong ? (Long.compare(a.priorityAsLong, b.priorityAsLong))
                                         : (Double.compare(a.priority,       b.priority      ));

    public static final Comparator<PermissionGroup> priorityComparatorHighestFirst
            = (a, b) -> a.priorityIsLong ? (-Long  .compare(a.priorityAsLong, b.priorityAsLong))
                                         : (-Double.compare(a.priority,       b.priority      ));

    String name;
    double priority;
    long priorityAsLong;
    boolean priorityIsLong;

    PermissionSet permissionSet = new PermissionSet();
    SortedSet<PermissionGroup> referencedGroups = new TreeSet<>(priorityComparatorHighestFirst);

    public String getName()
    { return name; }

    public double getPriority()
    { return priority; }

    public long getPriorityAsLong()
    { return priorityAsLong; }

    public String getPriorityAsString()
    { return priorityIsLong ? Long.toString(priorityAsLong) : Double.toString(priority); }

    private PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
    {
        PermissionSet.PermissionWithPath mrp = permissionSet.getMostRelevantPermission(permissionAsString);

        if(mrp != null)
            return mrp;

        for(PermissionGroup permGroup : referencedGroups)
        {
            mrp = permGroup.permissionSet.getMostRelevantPermission(permissionAsString);

            if(mrp != null)
                return mrp;
        }

        return null;
    }

    public void addPermission(String permissionAsString) throws ParseException
    { permissionSet.set(permissionAsString); }

    public boolean removePermission(String permissionPath)
    { return permissionSet.remove(permissionPath); }

    public void addPermissionGroup(PermissionGroup permGroup)
    { referencedGroups.add(permGroup); }

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
        String result = (priority == 0) ? (name) : (name + ": " + getPriorityAsString());
        result += "\n";

        for(PermissionGroup permGroup : referencedGroups)
            result += "\n    #" + permGroup.getName();

        return result + "\n" + permissionSet.toSaveString().replaceAll("^(?=.+)", "    ");
    }
}
