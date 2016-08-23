============
Contributing
============

****************
Issue submission
****************

| Issues are tracked on GitHub:
| https://github.com/secynic/ipwhois/issues


Follow the guidelines detailed in the appropriate section below. As a general
rule of thumb, provide as much information as possible when submitting issues.

Bug reports
===========

- Title should be a short, descriptive summary of the bug
- Include the Python and ipwhois versions affected
- Provide a context (with code example) in the description of your issue. What
  are you attempting to do?
- Include the full obfuscated output. Make sure to set DEBUG logging:
  ::

    import logging
    LOG_FORMAT = ('[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)s] '
       '[%(funcName)s()] %(message)s')
    logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)
- Include sources of information with links or screenshots
- Do you have a suggestion on how to fix the bug?

Feature Requests
================

- Title should be a short, descriptive summary of the feature requested
- Provide use case examples
- Include sources of information with links or screenshots
- Do you have a suggestion on how to implement the feature?

Testing
=======

You may have noticed that Travis CI tests are taking longer to complete.
This is due to the enabling of online lookup tests (network tests in the
ipwhois/tests/online directory).

When running local tests, you may include these tests by adding the
--include=online flag to your nosetests command.

Example::

    nosetests -v -w ipwhois --include=online

Questions
=========

I am happy to answer any questions and provide assistance where possible.
Please be clear and concise. Provide examples when possible. Check the
ipwhois `documentation <https://ipwhois.readthedocs.io/en/latest>`_ and the
`issue tracker <https://github.com/secynic/ipwhois/issues>`_ before asking a
question.

*************
Pull Requests
*************

What to include
===============

Aside from the core code changes, it is helpful to provide the following
(where applicable):

- Unit tests
- Examples
- Sphinx configuration changes in /data
- Requirements (python2.txt, python3.txt)

Guidelines
==========

- Title should be a short, descriptive summary of the changes
- Follow `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_ where possible.
- Follow the `Google docstring style guide
  <https://google.github.io/styleguide/pyguide.html#Comments>`_ for
  comments
- Must be compatible with Python 2.6, 2.7, and 3.3+
- Break out reusable code to functions
- Make your code easy to read and comment where necessary
- Reference the GitHub issue number in the description (e.g., Issue #01)
- When running nosetests, make sure to add the following arguments:
  ::

    --verbosity=3 --nologcapture --include=online --cover-erase
