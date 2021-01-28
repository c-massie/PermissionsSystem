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
        this.priorityIsLong = true;
    }

    public static final Comparator<PermissionGroup> priorityComparator
            = (a, b) -> a.priorityIsLong ? (Long.compare(a.priorityAsLong, b.priorityAsLong))
                                         : (Double.compare(a.priority,       b.priority      ));

    String name;
    double priority;
    long priorityAsLong;
    boolean priorityIsLong;

    PermissionSet permissionSet = new PermissionSet();
    SortedSet<PermissionGroup> referencedGroups = new TreeSet<>(priorityComparator);

    public void addPermission(String permissionAsString) throws ParseException
    { permissionSet.add(permissionAsString); }

    public void removePermission(String permissionPath)
    { permissionSet.remove(permissionPath); }

    public void addPermissionGroup(PermissionGroup permGroup)
    { referencedGroups.add(permGroup); }

    public void removePermissionGroup(PermissionGroup permissionGroup)
    { referencedGroups.remove(permissionGroup); }

    public boolean hasPermission(String permissionPath)
    { throw new UnsupportedOperationException("Not implemented yet."); }

    public boolean negatesPermission(String permissionPath)
    { throw new UnsupportedOperationException("Not implemented yet."); }
}
