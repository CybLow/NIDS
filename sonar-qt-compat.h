/**
 * @file sonar-qt-compat.h
 * @brief Force-included header for sonar-cxx analysis.
 *
 * Provides simplified macro definitions for Qt, compiler builtins, and
 * platform-specific tokens that the sonar-cxx preprocessor cannot resolve
 * from system headers alone.  This file is referenced via
 * sonar.cxx.forceIncludes in sonar-project.properties and is NOT compiled
 * by the real build.
 */
#ifndef SONAR_QT_COMPAT_H
#define SONAR_QT_COMPAT_H

/* ── Qt Core Macros ─────────────────────────────────────────────────── */
#ifndef Q_OBJECT
#define Q_OBJECT
#endif

#ifndef Q_GADGET
#define Q_GADGET
#endif

#ifndef Q_PROPERTY
#define Q_PROPERTY(...)
#endif

#ifndef Q_ENUM
#define Q_ENUM(...)
#endif

#ifndef Q_FLAG
#define Q_FLAG(...)
#endif

#ifndef Q_DECLARE_METATYPE
#define Q_DECLARE_METATYPE(...)
#endif

#ifndef Q_DISABLE_COPY
#define Q_DISABLE_COPY(...)
#endif

#ifndef Q_DISABLE_COPY_MOVE
#define Q_DISABLE_COPY_MOVE(...)
#endif

/* ── Qt Signal / Slot Keywords ──────────────────────────────────────── */
#ifndef signals
#define signals public
#endif

#ifndef slots
#define slots
#endif

#ifndef Q_SIGNALS
#define Q_SIGNALS public
#endif

#ifndef Q_SLOTS
#define Q_SLOTS
#endif

#ifndef emit
#define emit
#endif

#ifndef Q_EMIT
#define Q_EMIT
#endif

#ifndef Q_INVOKABLE
#define Q_INVOKABLE
#endif

/* ── Qt Utility Macros ──────────────────────────────────────────────── */
#ifndef Q_UNUSED
#define Q_UNUSED(x) (void)(x)
#endif

#ifndef Q_ASSERT
#define Q_ASSERT(...)
#endif

#ifndef Q_NULLPTR
#define Q_NULLPTR nullptr
#endif

#ifndef Q_DECL_OVERRIDE
#define Q_DECL_OVERRIDE override
#endif

#ifndef Q_DECL_FINAL
#define Q_DECL_FINAL final
#endif

#ifndef Q_DECL_EXPORT
#define Q_DECL_EXPORT
#endif

#ifndef Q_DECL_IMPORT
#define Q_DECL_IMPORT
#endif

#ifndef Q_REQUIRED_RESULT
#define Q_REQUIRED_RESULT [[nodiscard]]
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

#ifndef QT_BEGIN_NAMESPACE
#define QT_BEGIN_NAMESPACE
#endif

#ifndef QT_END_NAMESPACE
#define QT_END_NAMESPACE
#endif

/* ── Compiler Builtins ──────────────────────────────────────────────── */
#ifndef __has_include
#define __has_include(x) 0
#endif

#ifndef __has_cpp_attribute
#define __has_cpp_attribute(x) 0
#endif

#ifndef __attribute__
#define __attribute__(...)
#endif

#ifndef __declspec
#define __declspec(...)
#endif

#endif /* SONAR_QT_COMPAT_H */
