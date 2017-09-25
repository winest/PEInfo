from Singleton import *

class CHashItem :
    def __init__( aSelf , aSha256 = None , aSha1 = None , aMd5 = None ) :
        aSelf.sha256 = aSha256.lower() if aSha256 else None
        aSelf.sha1 = aSha1.lower() if aSha1 else None
        aSelf.md5 = aMd5.lower() if aMd5 else None

    def __eq__( aSelf , aOther ) :
        if ( aOther.sha256 != None and aOther.sha256 == aSelf.sha256 ) or \
           ( aOther.sha1 != None and aOther.sha1 == aSelf.sha1 ) or \
           ( aOther.md5 != None and aOther.md5 == aSelf.md5 ) :
            return True
        else :
            return False

    def __hash__( aSelf ) :
        return hash( aSelf.sha256 or aSelf.sha1 or aSelf.md5 )



class CHashes( metaclass = Singleton ) :
    def __init__( aSelf ) :
        aSelf.mapSha256Items = dict()
        aSelf.mapSha1Items = dict()
        aSelf.mapMd5Items = dict()

    def Add( aSelf , aHashItem ) :
        item = aSelf.Get( aHashItem )
        if item :            #Merge hashes if it's already exist
            item.sha256 = aHashItem.sha256 if not item.sha256 else item.sha256
            item.sha1 = aHashItem.sha1 if not item.sha1 else item.sha1
            item.md5 = aHashItem.md5 if not item.md5 else item.md5

            if item.md5 :
                aSelf.mapMd5Items[item.md5] = item
            if item.sha1 :
                aSelf.mapSha1Items[item.sha1] = item
            if item.sha256 :
                aSelf.mapSha256Items[item.sha256] = item
        else :
            if aHashItem.md5 :
                aSelf.mapMd5Items[aHashItem.md5] = aHashItem
            if aHashItem.sha1 :
                aSelf.mapSha1Items[aHashItem.sha1] = aHashItem
            if aHashItem.sha256 :
                aSelf.mapSha256Items[aHashItem.sha256] = aHashItem

    def Get( aSelf , aHashItem ) :
        if aHashItem.sha256 and aHashItem.sha256 in aSelf.mapSha256Items :
            return aSelf.mapSha256Items[aHashItem.sha256]
        elif aHashItem.sha1 and aHashItem.sha1 in aSelf.mapSha1Items :
            return aSelf.mapSha1Items[aHashItem.sha1]
        elif aHashItem.md5 and aHashItem.md5 in aSelf.mapMd5Items :
            return aSelf.mapMd5Items[aHashItem.md5]
        else :
            return None

    def Exists( aSelf , aHashItem ) :
        if aHashItem.sha256 and aHashItem.sha256 in aSelf.mapSha256Items :
            return True
        elif aHashItem.sha1 and aHashItem.sha1 in aSelf.mapSha1Items :
            return True
        elif aHashItem.md5 and aHashItem.md5 in aSelf.mapMd5Items :
            return True
        else :
            return False

    def Keys( aSelf ) :
        return ( set(aSelf.mapSha256Items.keys()) | set(aSelf.mapSha1Items.keys()) | set(aSelf.mapMd5Items.keys()) )
    def Values( aSelf ) :
        return ( set(aSelf.mapSha256Items.values()) | set(aSelf.mapSha1Items.values()) | set(aSelf.mapMd5Items.values()) )
    def ValuesCopy( aSelf ) :
        return aSelf.Values().copy()