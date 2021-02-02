
static PyObject* xweb_PY_class_new (Class* const parent, const char* const name, const uint nameSize) {

    Class* const new = malloc(sizeof(Class) + (parent ? parent->nameSize + 1 : 0) + nameSize);

    if (parent) {
        memcpy(new->name, parent->name, parent->nameSize);
        new->name[parent->nameSize] = '.';
        memcpy(new->name + parent->nameSize + 1, name, nameSize);
        new->nameSize = parent->nameSize + 1 + nameSize;
    } else {
        memcpy(new->name, name, nameSize);
        new->nameSize = nameSize;
    }

    new->childs = NULL;
    new->threads = NULL;
    new->n = 0;
    new->nMax = 0;
    new->reserved = 0;
    new->reserved2 = 0;
    new->next = classes;

    if ((new->parent = parent)) {
        new->parentNext = parent->childs;
        new->parent->childs = new;
        new->site = parent->site;
    } else { // É UMA CLASSE ROOT, ENTÃO CRIA UM SITE

        Site* const site = malloc(sizeof(Site));

        site->classes = NULL;
        site->ip4Next = 0;
        site->ip6Next = 0;
        site->proxiesCount = 0;
        site->proxiesNext = 0;
        site->class = new;
        site->next = sites;

        sites = site;

        foreach (i, PROXIES_N)
            site->proxies[i] = i;

        memset(site->proxiesPoints, PROXY_POINTS_ZERO, PROXIES_N);

        new->parentNext = NULL;
        new->site = site;
    }

    // CADASTRA ESTA CLASSE EM SEU SITE
    new->siteNext = new->site->classes;
    new->site->classes = new;

    // ESTAMOS NELA
    site = new->site;

    return PTR_TO_PY((classes = (class = new)));
}
