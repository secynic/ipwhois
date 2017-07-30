============
Contributing
============

.. note::

    If you are looking for items to contribute, start by looking at current
    open `issues <https://github.com/secynic/ipwhois/issues>`_ and search the
    source code for "TODO" items.

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

    nosetests -v -w ipwhois --include=online --exclude=stress --with-coverage
     --cover-package=ipwhois

Questions
=========

I am happy to answer any questions and provide assistance where possible.
Please be clear and concise. Provide examples when possible. Check the
ipwhois `documentation <https://ipwhois.readthedocs.io/en/latest>`_ and the
`issue tracker <https://github.com/secynic/ipwhois/issues>`_ before asking a
question.

Questions can be submitted as issues. Past questions can be searched by
filtering the label "question".

You can also message me on IRC. I am usually idle on freenode in the
`Python channels <https://www.python.org/community/irc/>`_

*************
Pull Requests
*************

What to include
===============

Aside from the core code changes, it is helpful to provide the following
(where applicable):

- Unit tests
- Examples
- Sphinx configuration changes in /docs
- Requirements (python2.txt, python3.txt, docs/requirements.txt)

GitFlow Model
=============

This library follows the GitFlow model. As a contributor, this is simply
accomplished by the following steps:

1. Create an issue (if there isn't one already)
2. Branch from dev (not master), try to name your branch to reference the issue
   (e.g., issue_123_feature, issue_123_bugfix).
3. Merge pull requests to dev (not master). Hotfix merges to master will
   only be allowed under extreme/time sensitive circumstances.

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

  If you would like to exclude the aggressive online stress tests, add to the
  above:
  ::

     --exclude stress

