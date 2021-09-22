/**
 * Common GLPI object
 **/
public class CommonGLPI {

    /// GLPI Item type cache : set dynamically calling getType
    protected int type = -1;

    /// Display list on Navigation Header
    protected boolean displaylist = true;

    /// Show Debug
    public boolean showdebug = false;

    /**
     * Tab orientation : horizontal or vertical.
     *
     * @value String
     */
    public String taborientation = "horizontal";

    /**
     * Rightname used to check rights to do actions on item.
     *
     * @value String
     */
    static String rightname = "";

    /**
     * Need to get item to show tab
     *
     * @value boolean
     */
    public boolean get_item_to_display_tab = false;
    static protected String othertabs[] = {};


    /**
     * Return the localized name of the current Type
     * Should be overloaded in each new class
     *
     * @param nb Number of items
     * @return String
     **/
    static String getTypeName(int... nb) {
        return "General";
    }


    /**
     * Return the simplified localized label of the current Type in the context of a form.
     * Avoid to recall the type in the label (Computer status -> Status)
     * <p>
     * Should be overloaded in each new class
     *
     * @return string
     **/
    static String getFieldLabel() {
        return getTypeName();
    }


    /**
     * Return the type of the object : class name
     *
     * @return string
     **/
    static void getType() {
        //return get_called_class();
    }

    private enum ObjectRight {
        READ,
        UPDATE,
        DELETE,
        PURGE,
        CREATE
    }

    /**
     * Check rights on CommonGLPI Object (without corresponding table)
     * Same signature as CommonDBTM::can but in case of this class, we don't check instance rights
     * so, id and input parameters are unused.
     *
     * @param $ID    ID of the item (-1 if new item)
     * @param $right Right to check : r / w / recursive / READ / UPDATE / DELETE
     * @param $input array of input data (used for adding item) (default NULL)
     * @return boolean
     **/
    boolean can(int $ID, ObjectRight $right, String[] $input) {
        switch ($right) {
            case READ:
                return canView();

            case UPDATE:
                return canUpdate();

            case DELETE:
                return canDelete();

            case PURGE:
                return canPurge();

            case CREATE:
                return canCreate();
        }
        return false;
    }


    /**
     * Have I the global right to "create" the Object
     * May be overloaded if needed (ex KnowbaseItem)
     *
     * @return boolean
     **/
    static boolean canCreate() {
        //if ( static::$rightname){
        //    return Session::haveRight ( static::$rightname, CREATE);
        //}
        return false;
    }


    /**
     * Have I the global right to "view" the Object
     * <p>
     * Default is true and check entity if the objet is entity assign
     * <p>
     * May be overloaded if needed
     *
     * @return boolean
     **/
    static boolean canView() {
//        if ( static::$rightname){
//            return Session::haveRight ( static::$rightname, READ);
//        }
        return false;
    }


    /**
     * Have I the global right to "update" the Object
     * <p>
     * Default is calling canCreate
     * May be overloaded if needed
     *
     * @return boolean
     **/
    static boolean canUpdate() {
//        if ( static::$rightname){
//            return Session::haveRight ( static::$rightname, UPDATE);
//        }
        return true;
    }


    /**
     * Have I the global right to "delete" the Object
     * <p>
     * May be overloaded if needed
     *
     * @return boolean
     **/
    static boolean canDelete() {
//        if ( static::$rightname){
//            return Session::haveRight ( static::$rightname, DELETE);
//        }
        return false;
    }


    /**
     * Have I the global right to "purge" the Object
     * <p>
     * May be overloaded if needed
     *
     * @return boolean
     **/
    static boolean canPurge() {
//        if ( static::$rightname){
//            return Session::haveRight ( static::$rightname, PURGE);
//        }
        return false;
    }


    /**
     * Register tab on an objet
     *
     * @param $typeform object class name to add tab on form
     * @param $typetab  object class name which manage the tab
     * @return void
     * @since 0.83
     **/
    static void registerStandardTab(String $typeform, String $typetab) {

//        if (isset(self::$othertabs[$typeform])){
//            self::$othertabs[$typeform][] =$typetab;
//        } else{
//            self::$othertabs[$typeform] = [$typetab];
//        }
    }


    /**
     * Get the array of Tab managed by other types
     * Getter for plugin (ex PDF) to access protected property
     *
     * @param $typeform class name to add tab on form
     * @return array array of types
     * @since 0.83
     **/
    static String[] getOtherTabs(String $typeform) {

//        if (isset(self::$othertabs[$typeform])){
//            return self::$othertabs[$typeform];
//        }
        return null;
    }


    /**
     * Define tabs to display
     * <p>
     * NB : Only called for existing object
     *
     * @param $options Options
     *                 - withtemplate is a template view ?
     * @return String[] array containing the tabs
     **/
    String[] defineTabs(String[] $options) {
        String[] $ong = new String[]{};
//        $this -> addDefaultFormTab($ong);
//        $this -> addImpactTab($ong, $options);
        return $ong;
    }


    /**
     * return all the tabs for current object
     *
     * @param $options Options
     *                 - withtemplate is a template view ?
     * @return array array containing the tabs
     * @since 0.83
     **/
    final String[] defineAllTabs(String[] $options) {
//        global $CFG_GLPI;

        String[] $onglets = new String[]{};
        // Tabs known by the object
//        if ($this -> isNewItem()) {
//            $this -> addDefaultFormTab($onglets);
//        } else {
//            $onglets = $this -> defineTabs($options);
//        }
//
//        // Object with class with 'addtabon' attribute
//        if (isset(self::$othertabs[$this -> getType()])
//          &&!$this -> isNewItem()){
//
//            foreach(self::$othertabs[$this -> getType()] as $typetab){
//                $this -> addStandardTab($typetab, $onglets, $options);
//            }
//        }
//
//        $class = $this -> getType();
//        if (($_SESSION['glpi_use_mode'] == Session::DEBUG_MODE)
//                && (!$this -> isNewItem() || $this -> showdebug)
//                && (method_exists($class, 'showDebug')
//                || Infocom::canApplyOn ($class)
//                || in_array($class, $CFG_GLPI["reservation_types"]))){
//
//            $onglets[-2] = __('Debug');
//        }
        return $onglets;
    }


    /**
     * Add standard define tab
     *
     * @param $itemtype itemtype link to the tab
     * @param $ong      defined tabs
     * @param $options  options (for withtemplate)
     * @return CommonGLPI
     **/
    CommonGLPI addStandardTab(int $itemtype, String[] $ong, String[] $options) {

//        $withtemplate = 0;
//        if (isset($options['withtemplate'])) {
//            $withtemplate = $options['withtemplate'];
//        }
//
//        switch ($itemtype) {
//            default:
//                if (!is_integer($itemtype)
//                        && ($obj = getItemForItemtype($itemtype))) {
//                    $titles = $obj -> getTabNameForItem($this, $withtemplate);
//                    if (!is_array($titles)) {
//                        $titles = [1 =>$titles];
//                    }
//
//                    foreach($titles as $key = > $val){
//                        if (!empty($val)) {
//                            $ong[$itemtype. '$'.$key] =$val;
//                        }
//                    }
//                }
//                break;
//        }
        return this;
    }

    /**
     * Add the impact tab if enabled for this item type
     *
     * @param $ong     defined tabs
     * @param $options options (for withtemplate)
     * @return CommonGLPI
     **/
    CommonGLPI addImpactTab(String[] $ong, String[] $options) {
//        global $CFG_GLPI;
//
//        // Check if impact analysis is enabled for this item type
//        if (Impact::isEnabled ( static::class)){
//            $this -> addStandardTab('Impact', $ong, $options);
//        }
        return this;
    }

    /**
     * Add default tab for form
     *
     * @param $ong Tabs
     * @return CommonGLPI
     * @since 0.85
     **/
    CommonGLPI addDefaultFormTab(String[] $ong) {
//
//        if (self::isLayoutExcludedPage ()
//                || !self::isLayoutWithMain ()
//                || !method_exists($this, "showForm")){
//            $ong[$this -> getType(). '$main'] =$this -> getTypeName(1);
//        }
        return this;
    }


    /**
     * get menu content
     *
     * @return array array for menu
     * @since 0.85
     **/
    static String[] getMenuContent() {

//        $menu = [];
//
//        $type = static::getType();
//        $item = new $type();
//        $forbidden = $type::getForbiddenActionsForMenu ();
//
//        if ($item instanceof CommonDBTM) {
//            if ($type::canView ()){
//                $menu['title'] = static::getMenuName();
//                $menu['shortcut'] = static::getMenuShorcut();
//                $menu['page'] = static::getSearchURL(false);
//                $menu['links']['search'] = static::getSearchURL(false);
//                $menu['icon'] = static::getIcon();
//
//                if (!in_array('add', $forbidden)
//                        && $type::canCreate ()){
//
//                    if ($item -> maybeTemplate()) {
//                        $menu['links']['add'] = '/front/setup.templates.php?'. 'itemtype='.$type.
//                        '&amp;add=1';
//                        if (!in_array('template', $forbidden)) {
//                            $menu['links']['template'] = '/front/setup.templates.php?'. 'itemtype='.$type.
//                            '&amp;add=0';
//                        }
//                    } else {
//                        $menu['links']['add'] = static::getFormURL(false);
//                    }
//                }
//
//                $extra_links = static::getAdditionalMenuLinks();
//                if (is_array($extra_links) && count($extra_links)) {
//                    $menu['links'] += $extra_links;
//                }
//
//            }
//        } else {
//            if (!method_exists($type, 'canView')
//                    || $item -> canView()) {
//                $menu['title'] = static::getMenuName();
//                $menu['shortcut'] = static::getMenuShorcut();
//                $menu['page'] = static::getSearchURL(false);
//                $menu['links']['search'] = static::getSearchURL(false);
//                if (method_exists($item, 'getIcon')) {
//                    $menu['icon'] = static::getIcon();
//                }
//            }
//        }
//        if ($data = static::getAdditionalMenuOptions()){
//            $menu['options'] = $data;
//        }
//        if ($data = static::getAdditionalMenuContent()){
//            $newmenu = [
//            strtolower($type) =>$menu,
//         ];
//            // Force overwrite existing menu
//            foreach($data as $key = > $val){
//                $newmenu[$key] = $val;
//            }
//            $newmenu['is_multi_entries'] = true;
//            $menu = $newmenu;
//        }
//        if (count($menu)) {
//            return $menu;
//        }
        return null;
    }


    /**
     * get additional menu content
     *
     * @return boolean array for menu
     * @since 0.85
     **/
    static boolean getAdditionalMenuContent() {
        return false;
    }


    /**
     * Get forbidden actions for menu : may be add / template
     *
     * @return String[] array of forbidden actions
     * @since 0.85
     **/
    static String[] getForbiddenActionsForMenu() {
        return null;
    }


    /**
     * Get additional menu options
     *
     * @return array array of additional options
     * @since 0.85
     **/
    static boolean getAdditionalMenuOptions() {
        return false;
    }


    /**
     * Get additional menu links
     *
     * @return array array of additional options
     * @since 0.85
     **/
    static boolean getAdditionalMenuLinks() {
        return false;
    }


    /**
     * Get menu shortcut
     *
     * @return string character menu shortcut key
     * @since 0.85
     **/
    static String getMenuShorcut() {
        return "";
    }


    /**
     * Get menu name
     *
     * @return string character menu shortcut key
     * @since 0.85
     **/
    static String getMenuName() {
//        return static::getTypeName(Session::getPluralNumber ());
        return "";
    }


    /**
     * Get Tab Name used for itemtype
     * <p>
     * NB : Only called for existing object
     * Must check right on what will be displayed + template
     *
     * @param $item         Item on which the tab need to be displayed
     * @param $withtemplate is a template object ? (default 0)
     * @return string tab name
     * @since 0.83
     **/
    String getTabNameForItem(CommonGLPI $item, boolean $withtemplate) {
        return "";
    }


    /**
     * show Tab content
     *
     * @param $item         Item on which the tab need to be displayed
     * @param $tabnum       tab number (default 1)
     * @param $withtemplate is a template object ? (default 0)
     * @return boolean
     * @since 0.83
     **/
    static boolean displayTabContentForItem(CommonGLPI $item, int $tabnum, boolean $withtemplate) {
        return false;
    }


    /**
     * display standard tab contents
     *
     * @param $item         Item on which the tab need to be displayed
     * @param $tab          tab name
     * @param $withtemplate is a template object ? (default 0)
     * @param $options      additional options to pass
     * @return boolean true
     **/
    static boolean displayStandardTab(CommonGLPI $item, String $tab, boolean $withtemplate, String[] $options) {

//        switch ($tab) {
//            // All tab
//            case -1:
//                // get tabs and loop over
//                $ong = $item -> defineAllTabs(['withtemplate' = > $withtemplate]);
//
//                if (!self::isLayoutExcludedPage () && self::isLayoutWithMain ()){
//                //on classical and vertical split; the main tab is always displayed
//                array_shift($ong);
//            }
//
//            if (count($ong)) {
//                foreach($ong as $key = > $val){
//                    if ($key != 'empty') {
//                        echo "<div class='alltab'>$val</div>";
//                        self::displayStandardTab ($item, $key, $withtemplate, $options);
//                    }
//                }
//            }
//            return true;
//
//            case -2:
//                $item -> showDebugInfo();
//                return true;
//
//            default:
//                $data = explode('$', $tab);
//                $itemtype = $data[0];
//                // Default set
//                $tabnum = 1;
//                if (isset($data[1])) {
//                    $tabnum = $data[1];
//                }
//
//                $options['withtemplate'] = $withtemplate;
//
//                if ($tabnum == 'main') {
//                    Plugin::doHook ('pre_show_item', ['item' =>$item, 'options' => &$options]);
//                    $ret = $item -> showForm($item -> getID(), $options);
//                    Plugin::doHook ('post_show_item', ['item' =>$item, 'options' =>$options]);
//                    return $ret;
//                }
//
//                if (!is_integer($itemtype) && ($itemtype != 'empty')
//                        && ($obj = getItemForItemtype($itemtype))) {
//                    $options['tabnum'] = $tabnum;
//                    $options['itemtype'] = $itemtype;
//                    Plugin::doHook ('pre_show_tab', ['item' =>$item, 'options' => &$options]);
//                    $ret = $obj -> displayTabContentForItem($item, $tabnum, $withtemplate);
//                    Plugin::doHook ('post_show_tab', ['item' =>$item, 'options' =>$options]);
//                    return $ret;
//                }
//                break;
//        }
        return false;

    }


    /**
     * create tab text entry
     *
     * @param $text text to display
     * @param $nb   number of items (default 0)
     * @return array array containing the onglets
     **/
    static String createTabEntry(String $text, int $nb) {

//        if ($nb) {
//            //TRANS: %1$s is the name of the tab, $2$d is number of items in the tab between ()
//            $text = sprintf(__('%1$s %2$s'), $text, "<sup class='tab_nb'>$nb</sup>");
//        }
        return $text;
    }


    /**
     * Redirect to the list page from which the item was selected
     * Default to the search engine for the type
     *
     * @return void
     **/
    void redirectToList() {
//        global $CFG_GLPI;
//
//        if (isset($_GET['withtemplate']) && !empty($_GET['withtemplate'])) {
//            Html::redirect ($CFG_GLPI["root_doc"]. "/front/setup.templates.php?add=0&itemtype=".$this->getType());
//
//        } else if (isset($_SESSION['glpilisturl'][$this -> getType()])
//                && !empty($_SESSION['glpilisturl'][$this -> getType()])) {
//            Html::redirect ($_SESSION['glpilisturl'][$this -> getType()]);
//
//        } else {
//            Html::redirect ($this -> getSearchURL());
//        }
    }


    /**
     * is the current object a new  one - Always false here (virtual Objet)
     *
     * @return boolean
     * @since 0.83
     **/
    boolean isNewItem() {
        return false;
    }


    /**
     * is the current object a new one - Always true here (virtual Objet)
     *
     * @param $ID Id to check
     * @return boolean
     * @since 0.84
     **/
    static boolean isNewID(int $ID) {
        return true;
    }


    /**
     * Get the search page URL for the current classe
     *
     * @param $full path or relative one (true by default)
     * @return string
     **/
    static boolean getTabsURL(boolean $full) {
        //return Toolbox::getItemTypeTabsURL (get_called_class(), $full);
        return true;
    }


    /**
     * Get the search page URL for the current class
     *
     * @param $full path or relative one (true by default)
     * @return string
     **/
    static String getSearchURL(boolean $full) {
//        return Toolbox::getItemTypeSearchURL (get_called_class(), $full);
        return "";
    }


    /**
     * Get the form page URL for the current class
     *
     * @param $full path or relative one (true by default)
     * @return string
     **/
    static String getFormURL(boolean $full) {
//        return Toolbox::getItemTypeFormURL (get_called_class(), $full);
        return "";
    }


    /**
     * Get the form page URL for the current class and point to a specific ID
     *
     * @param $id   Id (default 0)
     * @param $full Full path or relative one (true by default)
     * @return string
     * @since 0.90
     **/
    static String getFormURLWithID(int $id, boolean $full) {
        String $link ="";
//        $itemtype = get_called_class();
//        $link = $itemtype::getFormURL ($full);
//        $link. = (strpos($link, '?') ? '&' : '?'). 'id='.$id;
        return $link;
    }


    /**
     * Show primary form
     *
     * @param $options Options
     * @return boolean
     * @since 0.90
     **/
    boolean showPrimaryForm(String[] $options) {

//        if (!method_exists($this, "showForm")) {
//            return false;
//        }
//
//        $ong = $this -> defineAllTabs();
//        $class = "main_form";
//        if (count($ong) == 0) {
//            $class. = " no_tab";
//        }
//        if (!isset($_GET['id'])
//                || (($_GET['id'] <= 0) && !$this instanceof Entity)) {
//            $class. = " create_form";
//        } else {
//            $class. = " modify_form";
//        }
//        echo "<div class='form_content'>";
//        echo "<div class='$class'>";
//        Plugin::doHook ('pre_show_item', ['item' =>$this, 'options' => &$options]);
//        $this -> showForm($options['id'], $options);
//        Plugin::doHook ('post_show_item', ['item' =>$this, 'options' =>$options]);
//        echo "</div>";
//        echo "</div>";
        return true;
    }


    /**
     * Show tabs content
     *
     * @param $options parameters to add to URLs and ajax
     *                 - withtemplate is a template view ?
     * @return void
     * @since 0.85
     **/
    void showTabsContent(String[] $options) {

//        // for objects not in table like central
//        if (isset($this -> fields['id'])) {
//            $ID = $this -> fields['id'];
//        } else {
//            if (isset($options['id'])) {
//                $ID = $options['id'];
//            } else {
//                $ID = 0;
//            }
//        }
//
//        $target = $_SERVER['PHP_SELF'];
//        $extraparamhtml = "";
//        $withtemplate = "";
//        if (is_array($options) && count($options)) {
//            if (isset($options['withtemplate'])) {
//                $withtemplate = $options['withtemplate'];
//            }
//            $cleaned_options = $options;
//            if (isset($cleaned_options['id'])) {
//                unset($cleaned_options['id']);
//            }
//            if (isset($cleaned_options['stock_image'])) {
//                unset($cleaned_options['stock_image']);
//            }
//            if ($this instanceof CommonITILObject && $this -> isNewItem()) {
//                $this -> input = $cleaned_options;
//                $this -> saveInput();
//                // $extraparamhtml can be tool long in case of ticket with content
//                // (passed in GET in ajax request)
//                unset($cleaned_options['content']);
//            }
//
//            // prevent double sanitize, because the includes.php sanitize all data
//            $cleaned_options = Toolbox::stripslashes_deep ($cleaned_options);
//
//            $extraparamhtml = "&amp;".Toolbox::append_params ($cleaned_options, '&amp;');
//        }
//        echo "<div class='glpi_tabs ". ($this -> isNewID($ID) ? "new_form_tabs" : ""). "'>";
//        echo "<div id='tabspanel' class='center-h'></div>";
//        $onglets = $this -> defineAllTabs($options);
//        $display_all = true;
//        if (isset($onglets['no_all_tab'])) {
//            $display_all = false;
//            unset($onglets['no_all_tab']);
//        }
//
//        if (count($onglets)) {
//            $tabpage = $this -> getTabsURL();
//            $tabs = [];
//
//            foreach($onglets as $key = > $val){
//                $tabs[$key] = ['title' =>$val,
//                        'url' =>$tabpage,
//                        'params' =>"_target=$target&amp;_itemtype=".$this->getType().
//                "&amp;_glpi_tab=$key&amp;id=$ID$extraparamhtml"];
//            }
//
//            // Not all tab for templates and if only 1 tab
//            if ($display_all
//                    && empty($withtemplate)
//                    && (count($tabs) > 1)) {
//                $tabs[-1] = ['title' =>__('All'),
//                        'url' =>$tabpage,
//                        'params' =>"_target=$target&amp;_itemtype=".$this->getType().
//                "&amp;_glpi_tab=-1&amp;id=$ID$extraparamhtml"];
//            }
//
//            Ajax::createTabs ('tabspanel', 'tabcontent', $tabs, $this -> getType(), $ID,
//                    $this -> taborientation, $options);
//        }
//        echo "</div>";
    }


    /**
     * Show tabs
     *
     * @param $options parameters to add to URLs and ajax
     *                 - withtemplate is a template view ?
     * @return void
     **/
    void showNavigationHeader(String[] $options) {
//        global $CFG_GLPI;

//        // for objects not in table like central
//        if (isset($this -> fields['id'])) {
//            $ID = $this -> fields['id'];
//        } else {
//            if (isset($options['id'])) {
//                $ID = $options['id'];
//            } else {
//                $ID = 0;
//            }
//        }

//        $target = $_SERVER['PHP_SELF'];
//        $extraparamhtml = "";
//        $withtemplate = "";

//        if (is_array($options) && count($options)) {
//            $cleanoptions = $options;
//            if (isset($options['withtemplate'])) {
//                $withtemplate = $options['withtemplate'];
//                unset($cleanoptions['withtemplate']);
//            }
//            foreach(array_keys($cleanoptions)as $key) {
//                // Do not include id options
//                if (($key[0] == '_') || ($key == 'id')) {
//                    unset($cleanoptions[$key]);
//                }
//            }
//            $extraparamhtml = "&amp;".Toolbox::append_params ($cleanoptions, '&amp;');
//        }

//        if (empty($withtemplate)&& !$this -> isNewID($ID) && $this -> getType()&& $this -> displaylist) {

//            $glpilistitems =&$_SESSION['glpilistitems'][$this -> getType()];
//            $glpilisttitle =&$_SESSION['glpilisttitle'][$this -> getType()];
//            $glpilisturl =&$_SESSION['glpilisturl'][$this -> getType()];

//            if (empty($glpilisturl)) {
//                $glpilisturl = $this -> getSearchURL();
//            }

        // echo "<div id='menu_navigate'>";

//            $next = $prev = $first = $last = -1;
//            $current = false;
//            if (is_array($glpilistitems)) {
//                $current = array_search($ID, $glpilistitems);
//                if ($current != = false) {
//
//                    if (isset($glpilistitems[$current + 1])) {
//                        $next = $glpilistitems[$current + 1];
//                    }
//
//                    if (isset($glpilistitems[$current - 1])) {
//                        $prev = $glpilistitems[$current - 1];
//                    }
//
//                    $first = $glpilistitems[0];
//                    if ($first == $ID) {
//                        $first = -1;
//                    }
//
//                    $last = $glpilistitems[count($glpilistitems) - 1];
//                    if ($last == $ID) {
//                        $last = -1;
//                    }
//
//                }
//            }
//            $cleantarget = Html::cleanParametersURL ($target);
//            echo "<div class='navigationheader'>";

//            if ($first >= 0) {
//                echo "<a href='$cleantarget?id=$first$extraparamhtml'
//                class='navicon left' >
//                     <i class='fas fa-angle-double-left pointer' title =\"".__s('First'). "\"></i>
//                        </a > ";
//            }

//            if ($prev >= 0) {
////                echo "<a href='$cleantarget?id=$prev$extraparamhtml'
////                id = 'previouspage'
////                class='navicon left' >
////                     <i class='fas fa-angle-left pointer' title =\"".__s('Previous'). "\"></i>
////                        </a > ";
//
////                $js = '$("body").keydown(function(e) {
////                if ($("input, textarea").is(":focus") == = false) {
////                    if (e.keyCode == 37 && e.ctrlKey) {
////                        window.location = $("#previouspage").attr("href");
////                    }
////                }
////            });
////            ';
////            echo Html::scriptBlock($js);
//        }

//        if (!$glpilisttitle) {
//            $glpilisttitle = __s('List');
//        }

//        echo "<a href='$glpilisturl' title=\"$glpilisttitle\"
//        class='navicon left' >
//                  <i class='far fa-list-alt pointer' ></i >
//               </a > ";

//        $name = '';

//        if (isset($this -> fields['id']) && ($this instanceof CommonDBTM)) {
//            $name = $this -> getName();
//            if ($_SESSION['glpiis_ids_visible'] || empty($name)) {
//                $name = sprintf(__('%1$s - ID %2$d'), $name, $this -> fields['id']);
//            }
//        }

//        if (isset($this -> fields["entities_id"]) && Session::isMultiEntitiesMode () && $this -> isEntityAssign()){
//            $entname = Dropdown::getDropdownName ("glpi_entities", $this -> fields["entities_id"]);
//            if ($this -> isRecursive()) {
//                $entname = sprintf(__('%1$s + %2$s'), $entname, __('Child entities'));
//            }
//            $name = sprintf(__('%1$s (%2$s)'), $name, $entname);
//
//        }

//        echo "<span class='center nav_title'>&nbsp;";

//        if (!self::isLayoutWithMain () || self::isLayoutExcludedPage ()){
//            if ($this instanceof CommonITILObject) {
//                echo "<span class='status'>";
//                echo $this->getStatusIcon($this -> fields['status']);
//                echo "</span>";
//            }
//            echo $name;
//        }

//        echo "</span>";

//        $ma = new MassiveAction([
//                'item' = > [
//        $this -> getType() = > [
//        $this -> fields['id'] = > 1
//                  ]
//               ]
//            ],
//        $_GET,
//                'initial',
//                $this -> fields['id']
//         );

//        $actions = $ma -> getInput()['actions'];
//        $input = $ma -> getInput();

//        if ($this -> isEntityAssign()) {
//            $input['entity_restrict'] = $this -> getEntityID();
//        }

//        if (count($actions)) {
//            $rand = mt_rand();

//            if (count($actions)) {
//                echo "<span class='single-actions'>";
//                echo "<button type='button' class='btn btn-secondary moreactions'>
//                ".__(" Actions ")."
//                        < i class='fas fa-caret-down' ></i >
//                     </button > ";

//                echo "<div class='dropdown-menu' aria-labelledby='btnGroupDrop1'>";
//                foreach($actions as $key = > $action){
//                    echo "<a class='dropdown-item' data-action='$key' href='#'>$action</a>";
//                }
//                echo "</div>";
//                echo "</span>";
//            }

//            Html::openMassiveActionsForm ();
//            echo "<div id='dialog_container_$rand'></div>";
        // Force 'checkbox-zero-on-empty', because some massive actions can use checkboxes
//            $CFG_GLPI['checkbox-zero-on-empty'] = true;
//            Html::closeForm ();
        //restore
//            unset($CFG_GLPI['checkbox-zero-on-empty']);

//            echo Html::scriptBlock("$(function() {
//                    var ma = ".json_encode($input).";
//
//            $(document).on('click', '.moreactions', function() {
//                $('.moreactions + .dropdown-menu').toggle();
//            });
//
//            $(document).on('click', function(event) {
//                var target = $(event.target);
//                var parent = target.parent();
//
//                if (!target.hasClass('moreactions')
//                        && !parent.hasClass('moreactions')) {
//                    $('.moreactions + .dropdown-menu').hide();
//                }
//            });
//
//            $(document).on('click', '[data-action]', function() {
//                $('.moreactions + .dropdown-menu').hide();
//
//                var current_action = $(this).data('action');
//
//                $('<div></div>').dialog({
//                        title:ma.actions[current_action],
//                        width:500,
//                        height:'auto',
//                        modal:true,
//                        appendTo:'#dialog_container_$rand'
//                  }).load(
//                        '".$CFG_GLPI['root_doc ']. "/ajax/dropdownMassiveAction.php',
//                        Object.assign(
//                                {action:current_action},
//                ma
//                     )
//                  );
//            });
//        });
//        ");
//    }

//         if($current !==false)
//
//    {
//        echo "<span class='right navicon'>". ($current + 1). "/".count($glpilistitems). "</span>";
//    }

//         if($next >=0)
//
//    {
//        echo "<a href='$cleantarget?id=$next$extraparamhtml'
//        id = 'nextpage'
//        class='navicon right' > " .
//        "<i class='fas fa-angle-right pointer' title=\"".__s('Next'). "\"></i>
//            </a > ";
//        $js = '$("body").keydown(function(e) {
//        if ($("input, textarea").is(":focus") == = false) {
//            if (e.keyCode == 39 && e.ctrlKey) {
//                window.location = $("#nextpage").attr("href");
//            }
//        }
//    });';
//    echo Html::scriptBlock($js);
//}
//
//         if($last>=0){
//                 echo"<a href='$cleantarget?id=$last $extraparamhtml'
//class='navicon right'>" .
//        "<i class='fas fa-angle-double-right pointer' title=\"".__s('Last')."\"></i></a>";
//        }
//
//        echo"</div>"; // .navigationheader
//        }
    }


    /**
     * check if main is always display in current Layout
     *
     * @return boolean
     * @since 0.90
     */
    public static boolean isLayoutWithMain() {
//        return (isset($_SESSION['glpilayout']) && in_array($_SESSION['glpilayout'],['classic','vsplit']));
        return true;
    }


    /**
     * check if page is excluded for splitted layouts
     *
     * @return boolean
     * @since 0.90
     */
    public static boolean isLayoutExcludedPage() {
//        global $CFG_GLPI;

//        if (basename($_SERVER['SCRIPT_NAME']) == "updatecurrenttab.php") {
//            $base_referer = basename($_SERVER['HTTP_REFERER']);
//            $base_referer = explode("?", $base_referer);
//            $base_referer = $base_referer[0];
//            return in_array($base_referer, $CFG_GLPI['layout_excluded_pages']);
//        }
//
//        return in_array(basename($_SERVER['SCRIPT_NAME']), $CFG_GLPI['layout_excluded_pages']);
        return true;
    }


    /**
     * Display item with tabs
     *
     * @param $options Options
     * @return void
     * @since 0.85
     **/
    void display(String[] $options) {
//        global $CFG_GLPI;

//        if (isset($options['id']) && !$this -> isNewID($options['id'])) {
//            if (!$this -> getFromDB($options['id'])) {
//                Html::displayNotFoundError ();
//            }
//        }
//
//        // in case of lefttab layout, we couldn't see "right error" message
//        if ($this -> get_item_to_display_tab) {
//            if (isset($_GET["id"]) && $_GET["id"] && !$this -> can($_GET["id"], READ)) {
//                // This triggers from a profile switch.
//                // If we don't have right, redirect instead to central page
//                if (isset($_SESSION['_redirected_from_profile_selector'])
//                        && $_SESSION['_redirected_from_profile_selector']) {
//                    unset($_SESSION['_redirected_from_profile_selector']);
//                    Html::redirect ($CFG_GLPI['root_doc']. "/front/central.php");
//                }
//                Html::displayRightError ();
//            }
//        }
//
//        // try to lock object
//        // $options must contains the id of the object, and if locked by manageObjectLock will contains 'locked' => 1
//        ObjectLock::manageObjectLock (get_class($this), $options);
//
//        $this -> showNavigationHeader($options);
//        if (!self::isLayoutExcludedPage () && self::isLayoutWithMain ()){
//
//            if (!isset($options['id'])) {
//                $options['id'] = 0;
//            }
//            $this -> showPrimaryForm($options);
//        }
//
//        $this -> showTabsContent($options);
    }


    /**
     * List infos in debug tab
     *
     * @return void
     **/
    void showDebugInfo() {
//        global $CFG_GLPI;
//
//        if (method_exists($this, 'showDebug')) {
//            $this -> showDebug();
//        }
//
//        $class = $this -> getType();
//
//        if (Infocom::canApplyOn ($class)){
//            $infocom = new Infocom();
//            if ($infocom -> getFromDBforDevice($class, $this -> fields['id'])) {
//                $infocom -> showDebug();
//            }
//        }
//
//        if (in_array($class, $CFG_GLPI["reservation_types"])) {
//            $resitem = new ReservationItem();
//            if ($resitem -> getFromDBbyItem($class, $this -> fields['id'])) {
//                $resitem -> showDebugResa();
//            }
//        }
    }


    /**
     * Update $_SESSION to set the display options.
     *
     * @param $input        data to update
     * @param $sub_itemtype sub itemtype if needed (default '')
     * @return void
     * @since 0.84
     **/
    static void updateDisplayOptions(String[] $input, String $sub_itemtype) {

//        $options = static::getAvailableDisplayOptions();
//        if (count($options)) {
//            if (empty($sub_itemtype)) {
//                $display_options =&$_SESSION['glpi_display_options'][self::getType ()];
//            } else {
//                $display_options =&$_SESSION['glpi_display_options'][self::getType ()][$sub_itemtype];
//            }
//            // reset
//            if (isset($input['reset'])) {
//                foreach($options as $option_group) {
//                    foreach($option_group as $option_name = > $attributs){
//                        $display_options[$option_name] = $attributs['default'];
//                    }
//                }
//            } else {
//                foreach($options as $option_group) {
//                    foreach($option_group as $option_name = > $attributs){
//                        if (isset($input[$option_name]) && ($_GET[$option_name] == 'on')) {
//                            $display_options[$option_name] = true;
//                        } else {
//                            $display_options[$option_name] = false;
//                        }
//                    }
//                }
//            }
//            // Store new display options for user
//            if ($uid = Session::getLoginUserID ()){
//                $user = new User();
//                if ($user -> getFromDB($uid)) {
//                    $user -> update(['id' = > $uid,
//                            'display_options'
//                                    =>exportArrayToDB($_SESSION['glpi_display_options'])]);
//                }
//            }
//        }
    }


    /**
     * Load display options to $_SESSION
     *
     * @param $sub_itemtype sub itemtype if needed (default '')
     * @return void
     * @since 0.84
     **/
    static String[] getDisplayOptions(String $sub_itemtype) {
        String[] $display_options = new String[]{};

//        if (!isset($_SESSION['glpi_display_options'])) {
//            // Load display_options from user table
//            $_SESSION['glpi_display_options'] =[];
//            if ($uid = Session::getLoginUserID ()){
//                $user = new User();
//                if ($user -> getFromDB($uid)) {
//                    $_SESSION['glpi_display_options'] = importArrayFromDB($user -> fields['display_options']);
//                }
//            }
//        }
//        if (!isset($_SESSION['glpi_display_options'][self::getType ()])){
//            $_SESSION['glpi_display_options'][self::getType ()]=[];
//        }
//
//        if (!empty($sub_itemtype)) {
//            if (!isset($_SESSION['glpi_display_options'][self::getType ()][$sub_itemtype])){
//                $_SESSION['glpi_display_options'][self::getType ()][$sub_itemtype]=[];
//            }
//            $display_options =&$_SESSION['glpi_display_options'][self::getType ()][$sub_itemtype];
//        } else {
//            $display_options =&$_SESSION['glpi_display_options'][self::getType ()];
//        }
//
//        // Load default values if not set
//        $options = static::getAvailableDisplayOptions();
//        if (count($options)) {
//            foreach($options as $option_group) {
//                foreach($option_group as $option_name = > $attributs){
//                    if (!isset($display_options[$option_name])) {
//                        $display_options[$option_name] = $attributs['default'];
//                    }
//                }
//            }
//        }
        return $display_options;
    }


    /**
     * Show display options
     *
     * @param $sub_itemtype sub_itemtype if needed (default '')
     * @return void
     * @since 0.84
     **/
    static void showDislayOptions(String $sub_itemtype) {
//        global $CFG_GLPI;
//
//        $options = static::getAvailableDisplayOptions($sub_itemtype);
//
//        if (count($options)) {
//            if (empty($sub_itemtype)) {
//                $display_options = $_SESSION['glpi_display_options'][self::getType ()];
//            } else {
//                $display_options = $_SESSION['glpi_display_options'][self::getType ()][$sub_itemtype];
//            }
//            echo "<div class='center'>";
//            echo "\n<form method='get' action='".$CFG_GLPI['root_doc']. "/front/display.options.php'>\n";
//            echo "<input type='hidden' name='itemtype' value='NetworkPort'>\n";
//            echo "<input type='hidden' name='sub_itemtype' value='$sub_itemtype'>\n";
//            echo "<table class='tab_cadre'>";
//            echo "<tr><th colspan='2'>".__s('Display options'). "</th></tr>\n";
//            echo "<tr><td colspan='2'>";
//            echo "<input type='submit' class='submit' name='reset' value=\"".
//                    __('Reset display options'). "\">";
//            echo "</td></tr>\n";
//
//            foreach($options as $option_group_name = > $option_group){
//                if (count($option_group) > 0) {
//                    echo "<tr><th colspan='2'>$option_group_name</th></tr>\n";
//                    foreach($option_group as $option_name = > $attributs){
//                        echo "<tr>";
//                        echo "<td>";
//                        echo "<input type='checkbox' name='$option_name' ".
//                        ($display_options[$option_name] ? 'checked' : ''). ">";
//                        echo "</td>";
//                        echo "<td>".$attributs['name']. "</td>";
//                        echo "</tr>\n";
//                    }
//                }
//            }
//            echo "<tr><td colspan='2' class='center'>";
//            echo "<input type='submit' class='submit' name='update' value=\""._sx('button', 'Save'). "\">";
//            echo "</td></tr>\n";
//            echo "</table>";
//            echo "</form>";
//
//            echo "</div>";
//        }
    }


    /**
     * Get available display options array
     *
     * @return array all the options
     * @since 0.84
     **/
    static String[] getAvailableDisplayOptions() {
        return new String[]{};
    }


    /**
     * Get link for display options
     *
     * @param $sub_itemtype sub itemtype if needed for display options
     * @return string
     * @since 0.84
     **/
    static String getDisplayOptionsLink(String $sub_itemtype) {
        String $link = "";
//        global $CFG_GLPI;
//
//        $rand = mt_rand();
//
//        $link = "<span class='fa fa-wrench pointer' title=\"";
//        $link. = __s('Display options'). "\" ";
//        $link. = " onClick=\"".Html::jsGetElementbyID ("displayoptions".$rand). ".dialog('open');\"";
//        $link. = "><span class='sr-only'>".__s('Display options'). "</span></span>";
//        $link. = Ajax::createIframeModalWindow ("displayoptions".$rand,
//                $CFG_GLPI['root_doc'].
//        "/front/display.options.php?itemtype=".
//        static::getType(). "&sub_itemtype=$sub_itemtype",
//        ['display' =>false,
//                'width' =>600,
//                'height' =>500,
//                'reloadonclose' =>true]);

        return $link;
    }


    /**
     * Get error message for item
     *
     * @param $error  error type see define.php for ERROR_*
     * @param $object string to use instead of item link (default '')
     * @return string
     * @since 0.85
     **/
    String getErrorMessage(int $error, String $object) {

//        if (empty($object)) {
//            $object = $this -> getLink();
//        }
//        switch ($error) {
//            case ERROR_NOT_FOUND:
//                return sprintf(__('%1$s: %2$s'), $object, __('Unable to get item'));
//
//            case ERROR_RIGHT:
//                return sprintf(__('%1$s: %2$s'), $object, __('Authorization error'));
//
//            case ERROR_COMPAT:
//                return sprintf(__('%1$s: %2$s'), $object, __('Incompatible items'));
//
//            case ERROR_ON_ACTION:
//                return sprintf(__('%1$s: %2$s'), $object, __('Error on executing the action'));
//
//            case ERROR_ALREADY_DEFINED:
//                return sprintf(__('%1$s: %2$s'), $object, __('Item already defined'));
//        }
        return "";
    }
}