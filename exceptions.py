class BadPaddingException(Exception):
    """
    Raised when the padding is incorrect
    """


class BlockSizeUnidentifiableException(Exception):
    """
    Raised when the block size is unidentifiable
    """


class BlockCipherModeUnidentifiableException(Exception):
    """
    Raised when the block cipher mode is unidentifiable
    """


class CategoryNotDeterminedException(Exception):
    """
    Raised when the category is not determined
    """
