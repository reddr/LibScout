/*
 * Copyright (c) 2015-2016  Erik Derr [derr@cs.uni-saarland.de]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package de.infsec.tpl.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * Class containing constants for the well-known Android lifecycle methods
 * @author Erik Derr
 */
public class AndroidEntryPointConstants {
	
	// Class constants
	public static final String ACTIVITYCLASS = "android.app.Activity";
	public static final String FRAGMENTCLASS = "android.app.Fragment";
	public static final String SUPPORTFRAGMENTCLASS = "android.support.v4.app.Fragment";
	public static final String SERVICECLASS = "android.app.Service";
	public static final String BROADCASTRECEIVERCLASS = "android.content.BroadcastReceiver";
	public static final String CONTENTPROVIDERCLASS = "android.content.ContentProvider";
	public static final String APPLICATIONCLASS = "android.app.Application";
	public static final String ASYNCTASKCLASS = "android.os.AsyncTask";
	public static final String RUNNABLECLASS = "java.lang.Runnable";
	public static final String CALLABLECLASS = "java.util.concurrent.Callable";
	public static final String THREADCLASS = "java.lang.Thread";
	public static final String HANDLERCLASS = "android.os.Handler";
	public static final String OBJECTCLASS = "java.lang.Object";
	
	public static final String VIEWGROUP_TYPE = "android.view.ViewGroup";
	public static final String VIEW_TYPE = "android.view.View";
	public static final String WEBVIEW_TYPE = "android.webkit.WebView";
	public static final String RUNNABLE_TYPE = "java.lang.Runnable";

	
	// Activity lifecycle callback selectors
	public static final String ACTIVITY_ONCREATE = "onCreate(Landroid/os/Bundle;)V";
	public static final String ACTIVITY_ONSTART = "onStart()V";
	public static final String ACTIVITY_ONRESUME = "onResume()V";
	public static final String ACTIVITY_ONPOSTRESUME = "onPostResume()V";
	public static final String ACTIVITY_ONRESTOREINSTANCESTATE = "onRestoreInstanceState(Landroid/os/Bundle;)V";
	public static final String ACTIVITY_ONPOSTCREATE = "onPostCreate(Landroid/os/Bundle;)V";
	public static final String ACTIVITY_ONSAVEINSTANCESTATE = "onSaveInstanceState(Landroid/os/Bundle;)V";
	public static final String ACTIVITY_ONPAUSE = "onPause()V";
	public static final String ACTIVITY_ONSTOP = "onStop()V";
	public static final String ACTIVITY_ONRESTART = "onRestart()V";
	public static final String ACTIVITY_ONDESTROY = "onDestroy()V";
	public static final String ACTIVITY_ONACTIVITYRESULT = "onActivityResult(IILandroid/content/Intent;)V";
	public static final String ACTIVITY_ONNEWINTENT = "onNewIntent(Landroid/content/Intent;)V";

	// Fragment lifecycle callback selectors
	public static final String FRAGMENT_ONATTACH = "onAttach(Landroid/app/Activity;)V";
	public static final String FRAGMENT_ONCREATE = "onCreate(Landroid/os/Bundle;)V";
	public static final String FRAGMENT_ONCREATEVIEW = "onCreateView(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Landroid/os/Bundle;)Landroid/view/View;";
	public static final String FRAGMENT_ONACTIVITYCREATED = "onActivityCreated(Landroid/os/Bundle;)V";
	public static final String FRAGMENT_ONVIEWSTATERESTORED = "onViewStateRestored(Landroid/os/Bundle;)V";
	public static final String FRAGMENT_ONSTART = "onStart()V";
	public static final String FRAGMENT_ONRESUME = "onResume()V";
	public static final String FRAGMENT_ONPAUSE = "onPause()V";
	public static final String FRAGMENT_ONSTOP = "onStop()V";
	public static final String FRAGMENT_ONDESTROYVIEW = "onDestroyView()V";
	public static final String FRAGMENT_ONDESTROY = "onDestroy()V";
	public static final String FRAGMENT_ONDETACH = "onDetach()V";
		
	// Service lifecycle callback selectors
	public static final String SERVICE_ONCREATE = "onCreate()V";
	public static final String SERVICE_ONSTART = "onStart(Landroid/content/Intent;I)V";
	public static final String SERVICE_ONSTARTCOMMAND = "onStartCommand(Landroid/content/Intent;II)I";
	public static final String SERVICE_ONBIND = "onBind(Landroid/content/Intent;)Landroid/os/IBinder;";
	public static final String SERVICE_ONREBIND = "onRebind(Landroid/content/Intent;)V";
	public static final String SERVICE_ONUNBIND = "onUnbind(Landroid/content/Intent;)Z";
	public static final String SERVICE_ONDESTROY = "onDestroy()V";
	
	// BroadcastReceiver lifecycle callback selectors
	public static final String BROADCAST_ONRECEIVE = "onReceive(Landroid/content/Context;Landroid/content/Intent;)V";
	
	// ContentProvider lifecycle callback selectors
	public static final String CONTENTPROVIDER_ONCREATE = "onCreate()Z";
	
	// All other AsyncTask lifecycle methods have varying parameter types and have therefore to be generated
	public static final String ASYNCTASK_ONPREEXECUTE = "onPreExecute()V";
	public static final String ASYNCTASK_ONCANCELLED = "onCancelled()V";
	
	public static final String APPLICATION_ONCREATE = "onCreate()V";
	public static final String APPLICATION_ONTERMINATE = "onTerminate()V";

	public static final String APPLIFECYCLECALLBACK_ONACTIVITYSTARTED = "onActivityStarted(Landroid/app/Activity;)V";
	public static final String APPLIFECYCLECALLBACK_ONACTIVITYSTOPPED = "onActivityStopped(Landroid/app/Activity;)V";
	public static final String APPLIFECYCLECALLBACK_ONACTIVITYSAVEINSTANCESTATE = "onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V";
	public static final String APPLIFECYCLECALLBACK_ONACTIVITYRESUMED = "onActivityResumed(Landroid/app/Activity;)V";
	public static final String APPLIFECYCLECALLBACK_ONACTIVITYPAUSED = "onActivityPaused(Landroid/app/Activity;)V";
	public static final String APPLIFECYCLECALLBACK_ONACTIVITYDESTROYED = "onActivityDestroyed(Landroid/app/Activity;)V";
	public static final String APPLIFECYCLECALLBACK_ONACTIVITYCREATED = "onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V";
	
	// Activity lifecycle callback methods
	private static final String[] activityMethods = {
		ACTIVITY_ONCREATE, ACTIVITY_ONSTART, ACTIVITY_ONRESUME, ACTIVITY_ONPOSTRESUME, ACTIVITY_ONRESTOREINSTANCESTATE, ACTIVITY_ONPOSTCREATE,
		ACTIVITY_ONSAVEINSTANCESTATE, ACTIVITY_ONPAUSE, ACTIVITY_ONSTOP, ACTIVITY_ONRESTART, ACTIVITY_ONDESTROY,
		ACTIVITY_ONACTIVITYRESULT, ACTIVITY_ONNEWINTENT
	};
	
	private static final String[] serviceMethods = {
		SERVICE_ONCREATE, SERVICE_ONDESTROY, SERVICE_ONSTART,
		SERVICE_ONSTARTCOMMAND, SERVICE_ONBIND, SERVICE_ONREBIND, SERVICE_ONUNBIND
	};
	
	private static final String[] broadcastMethods = { BROADCAST_ONRECEIVE };
	
	private static final String[] contentproviderMethods = { CONTENTPROVIDER_ONCREATE };
	
	private static final String[] applicationMethods = {
		APPLICATION_ONCREATE, APPLICATION_ONTERMINATE, APPLIFECYCLECALLBACK_ONACTIVITYSTARTED,
		APPLIFECYCLECALLBACK_ONACTIVITYSTOPPED, APPLIFECYCLECALLBACK_ONACTIVITYSAVEINSTANCESTATE,
		APPLIFECYCLECALLBACK_ONACTIVITYRESUMED, APPLIFECYCLECALLBACK_ONACTIVITYPAUSED,
		APPLIFECYCLECALLBACK_ONACTIVITYDESTROYED, APPLIFECYCLECALLBACK_ONACTIVITYCREATED
	};
	
	private static final String[] fragmentMethods = {
		FRAGMENT_ONATTACH, FRAGMENT_ONCREATE, FRAGMENT_ONCREATEVIEW, FRAGMENT_ONACTIVITYCREATED,
		FRAGMENT_ONVIEWSTATERESTORED, FRAGMENT_ONSTART, FRAGMENT_ONRESUME, FRAGMENT_ONPAUSE,
		FRAGMENT_ONSTOP, FRAGMENT_ONDESTROYVIEW, FRAGMENT_ONDESTROY, FRAGMENT_ONDETACH
	};
	
	
	public static List<String> getLifecycleMethods(AndroidClassType type) {
		switch (type) {
			case Activity:
				return getActivityLifecycleMethods();
			case Application:
				return getApplicationLifecycleMethods();
//			case AsyncTask:
//				see getAsyncTaskLifecycleMethods
			case BroadcastReceiver:
				return getBroadcastLifecycleMethods();
			case ContentProvider:
				return getContentproviderLifecycleMethods();
			case Fragment:
				return getFragmentLifecycleMethods();
			case Service:
				return getServiceLifecycleMethods();
			default:
				return new ArrayList<String>();
		}
	}
	
	public static List<String> getActivityLifecycleMethods(){
		return Arrays.asList(activityMethods);
	}

	public static List<String> getFragmentLifecycleMethods(){
		return Arrays.asList(fragmentMethods);
	}
	
	public static List<String> getServiceLifecycleMethods(){
		return Arrays.asList(serviceMethods);
	}
	
	public static List<String> getBroadcastLifecycleMethods(){
		return Arrays.asList(broadcastMethods);
	}
	
	public static List<String> getContentproviderLifecycleMethods(){
		return Arrays.asList(contentproviderMethods);
	}
	

	public static List<String> getApplicationLifecycleMethods(){
		return Arrays.asList(applicationMethods);
	}
}
