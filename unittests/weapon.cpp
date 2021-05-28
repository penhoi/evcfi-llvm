#include <iostream>
using namespace std;

class Weapon
{
public:
    virtual void loadFeatures() = 0;
};

class Bomb : public Weapon
{
public:
    virtual void loadFeatures() override
    {
        cout << "Loading bomb features.\n";
    }
};

class Gun : public Weapon
{
public:
    virtual void loadFeatures() override
    {
        cout << "Loading gun features.\n";
    }
};

int main(int argc, char *argv[])
{
    Weapon *w = NULL;

    switch (argc % 2)
    {
    case 0:
        w = new Bomb();
        break;
    case 1:
        w = new Gun();
        break;
    }

    w->loadFeatures();
    return 0;
}
