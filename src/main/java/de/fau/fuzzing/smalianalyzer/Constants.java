package de.fau.fuzzing.smalianalyzer;

import com.google.common.collect.Sets;

import java.util.Set;

public class Constants
{
    public static final Set<String> ANDROID_COMPONENTS = Sets.newHashSet(
            // activities
            "Landroid/app/Activity;",
            "Landroid/accounts/AccountAuthenticatorActivity;",
            "android/app/ActivityGroup;",
            "Landroid/app/AliasActivity;",
            "Landroid/app/AliasActivity;",
            "Landroid/app/ListActivity;",
            "Landroid/app/NativeActivity;",
            // services
            "Landroid/app/Service;",
            // receivers
            "Landroid/content/BroadcastReceiver;",
            "Landroid/appwidget/AppWidgetProvider;",
            "Landroid/app/admin/DeviceAdminReceiver;",
            "Landroid/telephony/mbms/MbmsDownloadReceiver;",
            "Landroid/service/restrictions/RestrictionsReceiver;"
    );

    public static final Set<String> COMPONENT_ENTRY_METHODS = Sets.newHashSet(
            // activity
            "onCreate(Landroid/os/Bundle;)V",
            // service
            "onCreate()V",
            "onStartCommand(Landroid/content/Intent;II)I",
            "onBind(Landroid/content/Intent;)Landroid/os/IBinder;",
            // receiver
            "onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
    );

    public static final String INTENT_CLASS = "Landroid/content/Intent;";
    public static final String BUNDLE_CLASS = "Landroid/os/Bundle;";
    public static final String PARCABLE_CLASS = "Landroid/os/Parcelable;";
}
