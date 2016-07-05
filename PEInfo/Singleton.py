class Singleton( type ) :
    _instances = {}
    def __call__( aClass , * aArgs , **kwargs ) :
        if aClass not in aClass._instances:
            aClass._instances[aClass] = super(Singleton , aClass).__call__(*aArgs , **kwargs)
        return aClass._instances[aClass]